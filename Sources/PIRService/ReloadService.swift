// Copyright 2024-2026 Apple Inc. and the Swift Homomorphic Encryption project authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Crypto
import Foundation
import Logging
import PrivacyPass
import PrivateInformationRetrieval
import ServiceLifecycle
import UnixSignals

struct SymmetricPirArguments: Codable, Hashable {
    /// Error encountered on resolving SymmetricPirArguments.
    struct ValidationError: Error {
        let message: String
    }

    /// File path for key with which database will be encrypted.
    ///
    /// This is required, but is an Optional to allow for clearer error message.
    let databaseEncryptionKeyFilePath: String?
    /// Config for Symmetric PIR.
    let configType: SymmetricPirConfigType?

    func resolve() throws -> SymmetricPirConfig {
        guard let databaseEncryptionKeyFilePath else {
            throw ValidationError(message: "'databaseEncryptionKeyFilePath' is missing in symmetric PIR configuration.")
        }
        let secretKeyString = try String(contentsOfFile: databaseEncryptionKeyFilePath, encoding: .utf8)
        guard let secretKey = Array(hexEncoded: secretKeyString) else {
            throw ValidationError(message: "Invalid OPRF key.")
        }
        let configType = configType ?? .OPRF_P384_AES_GCM_192_NONCE_96_TAG_128
        return try SymmetricPirConfig(oprfSecretKey: Secret(value: secretKey), configType: configType)
    }
}

struct ServerConfiguration: Codable {
    struct Usecase: Codable {
        let name: String
        let fileStem: String
        let shardCount: Int
        let versionCount: Int?
        let symmetricPirArguments: SymmetricPirArguments?
        var revision: String?
        var artifactSHA256: String?
        var bloomFile: String?
        var bloomSHA256: String?
    }

    struct Policy: Codable {
        let id: String
        let bearerTokenFile: String
        let privateKeyFile: String
        let nonceFile: String
        let usecases: [Usecase]
    }

    var profiles: [Policy]?
    let issuerRequestUri: String?
    let reportDirectory: String?
    let tokens: [String]
    let usecases: [Usecase]
}

actor ReloadService: Service {
    let configFile: URL
    let usecaseStore: UsecaseStore
    let privacyPassState: PrivacyPassState
    let reportStore: ReportStore
    let logger: Logger

    init(
        configFile: URL,
        usecaseStore: UsecaseStore,
        privacyPassState: PrivacyPassState,
        reportStore: ReportStore,
        logger: Logger)
    {
        self.configFile = configFile
        self.usecaseStore = usecaseStore
        self.privacyPassState = privacyPassState
        self.reportStore = reportStore
        self.logger = logger
    }

    func run() async throws {
        let signalSequence = await UnixSignalsSequence(trapping: .sighup)
        for await signal in signalSequence {
            guard signal == .sighup else {
                continue
            }

            logger.info("Reloading configuration...")
            do {
                try await reloadConfiguration()
                logger.info("Reloading configuration completed.")
            } catch {
                logger.error("Configuration reload failed; policy snapshot unchanged.")
            }
        }
    }

    func reloadConfiguration() async throws {
        let configData = try Data(contentsOf: configFile)
        let config = try JSONDecoder().decode(ServerConfiguration.self, from: configData)

        if let profiles = config.profiles {
            try await reloadPolicies(profiles, legacyTokens: config.tokens, legacyUsecases: config.usecases,
                                     reportDirectory: config.reportDirectory)
            return
        }
        guard await !privacyPassState.policyIsolation else { throw PolicyConfigurationError.invalid }

        await privacyPassState.update(allowList: Set(config.tokens))
        await reportStore.set(reportDirectory: config.reportDirectory)

        for usecase in config.usecases {
            // default to two versions
            let versionCount = usecase.versionCount ?? 2
            if versionCount == 0 {
                // special case, remove all versions
                try await usecaseStore.set(name: usecase.name, usecase: nil, versionCount: versionCount)
                return
            }
            let loaded = try loadUsecase(usecase: usecase)
            try await usecaseStore.set(name: usecase.name, usecase: loaded, versionCount: versionCount)
        }
    }

    private func reloadPolicies(_ profiles: [ServerConfiguration.Policy], legacyTokens: [String],
                                legacyUsecases: [ServerConfiguration.Usecase], reportDirectory: String?) async throws
    {
        // Never mix a global fallback or plaintext URL reporting into isolated mode.
        guard legacyTokens.isEmpty, legacyUsecases.isEmpty, reportDirectory == nil else {
            throw PolicyConfigurationError.invalid
        }
        var credentials: [PolicyCredential] = []
        var datasets: [PolicyDataset] = []
        var noncePaths = Set<String>()
        for profile in profiles {
            guard !profile.usecases.isEmpty, noncePaths.insert(profile.nonceFile).inserted else {
                throw PolicyConfigurationError.invalid
            }
            for path in [profile.bearerTokenFile, profile.privateKeyFile] {
                let attributes = try FileManager.default.attributesOfItem(atPath: path)
                guard let permissions = attributes[.posixPermissions] as? NSNumber,
                      permissions.intValue & 0o077 == 0 else { throw PolicyConfigurationError.invalid }
            }
            let bearer = try String(contentsOfFile: profile.bearerTokenFile, encoding: .utf8)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let pem = try String(contentsOfFile: profile.privateKeyFile, encoding: .utf8)
            let issuer = try PrivacyPass.Issuer(privateKey: .init(pemRepresentation: pem))
            let existingStore = await privacyPassState.nonceStore(for: issuer.publicKey.tokenKeyId)
            if let existingStore, existingStore.path != profile.nonceFile {
                throw PolicyConfigurationError.invalid
            }
            let binding = PolicyUsecase.digest([Data(profile.id.utf8), Data(issuer.publicKey.tokenKeyId)])
            let nonceStore = try existingStore ?? PolicyNonceStore(path: profile.nonceFile, binding: binding)
            credentials.append(.init(id: profile.id, bearer: bearer, issuer: issuer, nonceStore: nonceStore))
            var names = Set<String>()
            for usecase in profile.usecases {
                guard names.insert(usecase.name).inserted, let revision = usecase.revision,
                      let expected = usecase.artifactSHA256, let bloomFile = usecase.bloomFile,
                      let expectedBloom = usecase.bloomSHA256,
                      usecase.shardCount > 0, (1...8).contains(usecase.versionCount ?? 2)
                else {
                    throw PolicyConfigurationError.invalid
                }
                let before = try artifactDigest(usecase)
                let bloomDigest = try Data(SHA256.hash(data: Data(contentsOf: URL(fileURLWithPath: bloomFile))))
                guard before.hex == expected.lowercased(), bloomDigest.hex == expectedBloom.lowercased() else {
                    throw PolicyConfigurationError.invalid
                }
                let loaded = try loadUsecase(usecase: usecase)
                guard try artifactDigest(usecase) == before else { throw PolicyConfigurationError.invalid }
                let wrapped = try PolicyUsecase(base: loaded, policyID: profile.id, name: usecase.name,
                                                revision: revision, artifactDigest: before, bloomDigest: bloomDigest)
                datasets.append(.init(policyID: profile.id, name: usecase.name, usecase: wrapped,
                                      versionCount: usecase.versionCount ?? 2))
            }
        }
        try await privacyPassState.validate(credentials)
        try await usecaseStore.installPolicies(datasets)
        await privacyPassState.install(credentials)
    }

    private func artifactDigest(_ usecase: ServerConfiguration.Usecase) throws -> Data {
        // Immutable revision files; ordered, length-framed SHA256 matches PolicyUsecase.digest.
        var fields: [Data] = []
        for shard in 0..<usecase.shardCount {
            for suffix in ["params.txtpb", "bin"] {
                try fields.append(Data(contentsOf: URL(fileURLWithPath: "\(usecase.fileStem)-\(shard).\(suffix)")))
            }
        }
        return PolicyUsecase.digest(fields)
    }
}

private extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
