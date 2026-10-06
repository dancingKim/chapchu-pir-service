// Copyright 2026 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import HomomorphicEncryption
import HTTPTypes
import Hummingbird
import HummingbirdTesting
import Logging
@testable import PIRService
@testable import PIRServiceTesting
import PrivacyPass
import PrivateInformationRetrieval
import PrivateInformationRetrievalProtobuf
import Testing
import Util

struct PolicyIsolationTests {
    private typealias Client = PIRClient<MulPirClient<Bfv<UInt32>>>
    private let platform = Platform(osType: .iOS, osVersion: .init(major: 26, minor: 6))

    private func dataset(_ value: String, policy: String, revision: String = "1",
                         artifactStem: String? = nil) throws -> PolicyDataset
    {
        typealias Server = KeywordPirServer<MulPirServer<Bfv<UInt32>>>
        let context: Context<Server.Scheme> = try .init(encryptionParameters: .init(from: .n_4096_logq_27_28_28_logt_4))
        let rows = [KeywordValuePair(keyword: Array("common".utf8), value: Array(value.utf8)),
                    KeywordValuePair(keyword: Array("only-\(value)".utf8), value: [1])]
        let cuckoo = try CuckooTableConfig(hashFunctionCount: 2, maxEvictionCount: 100,
                                           maxSerializedBucketSize: context.bytesPerPlaintext,
                                           bucketCount: .fixedSize(bucketCount: 10))
        let config = try KeywordPirConfig(dimensionCount: 2, cuckooTableConfig: cuckoo,
                                          unevenDimensions: false, keyCompression: .noCompression)
        let processed = try Server.process(database: rows, config: config, with: context)
        if let artifactStem {
            try processed.database.save(to: "\(artifactStem)-0.bin")
            try processed.proto(context: context).save(to: "\(artifactStem)-0.params.txtpb")
        }
        let base = try PirUsecase(context: context, keywordParams: config.parameter,
                                  shards: [Server(context: context, processed: processed)])
        let identity = Data(SHA256.hash(data: Data(value.utf8)))
        let usecase = try PolicyUsecase(base: base, policyID: policy, name: "test", revision: revision,
                                        artifactDigest: identity, bloomDigest: identity)
        return PolicyDataset(policyID: policy, name: "test", usecase: usecase, versionCount: 2)
    }

    private func credential(_ id: String, key: PrivacyPass.PrivateKey? = nil,
                            store: PolicyNonceStore? = nil) throws -> PolicyCredential
    {
        try .init(id: id, bearer: "test-bearer-\(id)", issuer: .init(privateKey: key ?? .init()),
                  nonceStore: store ?? PolicyNonceStore())
    }

    private func install(_ credentials: [PolicyCredential], in state: PrivacyPassState) async throws {
        try await state.validate(credentials)
        await state.install(credentials)
    }

    @Test
    func realEncryptedQueriesIsolatePoliciesKeysAndRetainedRevisions() async throws {
        let store = UsecaseStore(), state = try PrivacyPassState()
        let a1 = try dataset("A", policy: "a"), b1 = try dataset("B", policy: "b")
        #expect(try a1.usecase.config().pirConfig == b1.usecase.config().pirConfig)
        try await store.installPolicies([a1, b1])
        try await install([credential("a"), credential("b")], in: state)
        let app = try await buildApplication(usecaseStore: store, privacyPassState: state)
        try await app.test(.live) { connection in // swiftlint:disable:this closure_body_length
            let sameOSIdentifier = UUID()
            var a = Client(
                connection: connection,
                userID: sameOSIdentifier,
                platform: platform,
                userToken: "test-bearer-a")
            var b = Client(
                connection: connection,
                userID: sameOSIdentifier,
                platform: platform,
                userToken: "test-bearer-b")
            #expect(try await a.request(keyword: "common") == "A")
            let bStatus: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigResponse = try await b.post(
                path: "/config",
                body: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigRequest.with { $0.usecases = ["test"] })
            #expect(bStatus.keyInfo.first?.timestamp == 0) // A's uploaded key is not B's key.
            #expect(try await b.request(keyword: "common") == "B")
            #expect(try await a.request(keyword: "common") == "A") // B's key upload cannot clobber A.
            #expect(try await a.request(keyword: "only-B") == nil)
            #expect(try await b.request(keyword: "only-A") == nil)
            #expect(a.configCache["test"]?.configurationId != b.configCache["test"]?.configurationId)

            var crossing = Client(connection: connection, userID: sameOSIdentifier, platform: platform,
                                  configCache: a.configCache, secretKeys: a.secretKeys, userToken: "test-bearer-b")
            await #expect { try await crossing.request(keyword: "common") } throws: { error in
                guard case let PIRClientError.serverError(status, _) = error else {
                    return false
                }
                return status == .gone
            }

            let a2 = try dataset("C", policy: "a", revision: "2")
            try await store.installPolicies([a2, b1])
            var newA = Client(connection: connection, platform: platform, userToken: "test-bearer-a")
            #expect(try await newA.request(keyword: "common") == "C")
            #expect(try await a.request(keyword: "common") == "A") // Exact old revision retry.
            #expect(try await b.request(keyword: "common") == "B")
            let colliding = try dataset("D", policy: "a", revision: "2")
            await #expect(throws: PolicyConfigurationError.self) { try await store.installPolicies([colliding, b1]) }
            #expect(try await newA.request(keyword: "common") == "C")
            try await store.installPolicies([
                .init(policyID: "a", name: "test", usecase: a2.usecase, versionCount: 1),
                b1,
            ])
            await #expect { try await a.request(keyword: "common") } throws: { error in
                guard case let PIRClientError.serverError(status, _) = error else {
                    return false
                }
                return status == .gone
            }
        }
    }

    @Test
    func tokensRejectConcurrentReplayAndFullKeyIDTampering() async throws {
        let store = UsecaseStore(), state = try PrivacyPassState()
        try await store.installPolicies([dataset("A", policy: "a")])
        try await install([credential("a")], in: state)
        let app = try await buildApplication(usecaseStore: store, privacyPassState: state)
        try await app.test(.live) { connection in
            var client = Client(connection: connection, platform: platform, userToken: "test-bearer-a")
            try await client.fetchTokens(count: 2)
            let token = client.tokens.removeFirst()
            let userIdentifierHeader = try #require(HTTPField.Name("User-Identifier"))
            let headers: HTTPFields = [.authorization: "PrivateToken token=\(token.bytes().base64URLEncodedString())",
                                       userIdentifierHeader: client.userID.uuidString,
                                       .userAgent: platform.exampleUserAgent]
            let body: [UInt8] = try Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigRequest().serializedBytes()
            async let first = connection.post(path: "/config", body: body, headers: headers)
            async let second = connection.post(path: "/config", body: body, headers: headers)
            let statuses = try await [first.status.code, second.status.code].sorted()
            #expect(statuses == [200, 401])
            let again = try await connection.post(path: "/config", body: body, headers: headers)
            #expect(again.status == .unauthorized)
            var bytes = client.tokens.removeFirst().bytes()
            // Token layout: type(2), nonce(32), challenge(32), keyID(32). Preserve its last byte.
            bytes[66] ^= 1
            var tampered = headers
            tampered[.authorization] = "PrivateToken token=\(bytes.base64URLEncodedString())"
            let rejected = try await connection.post(path: "/config", body: body, headers: tampered)
            #expect(rejected.status == .unauthorized)
        }
    }

    @Test
    func policyModeRejectsAnonymousConfigUnsupportedPlatformAndURLReports() async throws {
        let state = try PrivacyPassState(), store = UsecaseStore()
        try await install([credential("a")], in: state)
        try await store.installPolicies([dataset("A", policy: "a")])
        let app = try await buildApplication(usecaseStore: store, privacyPassState: state)
        try await app.test(.live) { connection in
            let config = try await connection.get(path: "/config", body: [], headers: [:])
            #expect(config.status == .notImplemented)
            var unsupported = Client(connection: connection, platform: .iOS27_3, userToken: "test-bearer-a")
            await #expect { try await unsupported.request(keyword: "common") } throws: { error in
                guard case let PIRClientError.serverError(status, _) = error else {
                    return false
                }
                return status == .notImplemented
            }
            var current = Client(connection: connection, platform: platform, userToken: "test-bearer-a")
            await #expect {
                let _: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigResponse = try await current.post(
                    path: "/config", body: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigRequest.with { config in
                        config.usecases = ["test", "test"]
                    })
            } throws: { error in
                guard case let PIRClientError.serverError(status, _) = error else {
                    return false
                }
                return status == .badRequest
            }
            try await current.fetchTokens(count: 1)
            let headers: HTTPFields =
                [.authorization: "PrivateToken token=\(current.tokens[0].bytes().base64URLEncodedString())"]
            let report = try await connection.post(path: "/report", body: [], headers: headers)
            #expect(report.status == .notImplemented)
        }
    }

    @Test
    func nonceJournalSurvivesRestartAndRejectsSecondWriter() async throws {
        let path = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        defer { try? FileManager.default.removeItem(atPath: path) }
        func firstProcess() async throws {
            let journal = try PolicyNonceStore(path: path)
            try await journal.store(nonce: Array(repeating: 7, count: 32))
            #expect(throws: (any Error).self) { try PolicyNonceStore(path: path) }
        }
        try await firstProcess()
        let restarted = try PolicyNonceStore(path: path)
        #expect(try await restarted.contains(nonce: Array(repeating: 7, count: 32)))
        await #expect(throws: PolicyConfigurationError.self) {
            try await restarted.store(nonce: Array(repeating: 7, count: 32))
        }
    }

    @Test
    func credentialCollisionDoesNotChangeInstalledPolicy() async throws {
        let state = try PrivacyPassState()
        let a = try credential("a")
        try await install([a], in: state)
        let stolenKey = try credential("b", key: a.issuer.privateKey)
        await #expect(throws: PolicyConfigurationError.self) { try await state.validate([stolenKey]) }
        #expect(await state.issuer(for: a.bearer)?.publicKey.tokenKeyId == a.issuer.publicKey.tokenKeyId)
    }

    @Test
    func externalConfigRequiresMatchingArtifactsAndKeepsPreviousSnapshotOnFailure() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let stem = directory.appendingPathComponent("r1").path
        _ = try dataset("A", policy: "external", artifactStem: stem)
        let key = try PrivacyPass.PrivateKey()
        let keyFile = directory.appendingPathComponent("issuer.pem")
        let bearerFile = directory.appendingPathComponent("bearer")
        let bloomFile = directory.appendingPathComponent("bloom")
        try Data(key.pemRepresentation.utf8).write(to: keyFile)
        try Data("test-external-bearer".utf8).write(to: bearerFile)
        for url in [keyFile, bearerFile] {
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
        let bloom = Data([1, 2, 3])
        try bloom.write(to: bloomFile)
        let artifacts = try ["params.txtpb", "bin"]
            .map { try Data(contentsOf: URL(fileURLWithPath: "\(stem)-0.\($0)")) }
        func hex(_ data: Data) -> String {
            data.map { String(format: "%02x", $0) }.joined()
        }
        let config: [String: Any] = ["tokens": [], "usecases": [], "profiles": [[
            "id": "external", "bearerTokenFile": bearerFile.path, "privateKeyFile": keyFile.path,
            "nonceFile": directory.appendingPathComponent("nonce.journal").path,
            "usecases": [["name": "test", "fileStem": stem, "shardCount": 1, "revision": "1",
                          "artifactSHA256": hex(PolicyUsecase.digest(artifacts)), "bloomFile": bloomFile.path,
                          "bloomSHA256": hex(Data(SHA256.hash(data: bloom)))]],
        ]]]
        let configFile = directory.appendingPathComponent("config.json")
        try JSONSerialization.data(withJSONObject: config).write(to: configFile)
        let state = try PrivacyPassState(), store = UsecaseStore()
        let reload = ReloadService(configFile: configFile, usecaseStore: store, privacyPassState: state,
                                   reportStore: ReportStore(), logger: Logger(label: "policy-test"))
        try await reload.reloadConfiguration()
        let initial = try #require(await store.get(name: "test", policyID: "external"))
        let initialID = try initial.config().configID
        try await reload.reloadConfiguration() // same key, journal, revision is retry-safe.
        try Data([9]).write(to: bloomFile)
        await #expect(throws: PolicyConfigurationError.self) { try await reload.reloadConfiguration() }
        let retained = try #require(await store.get(name: "test", policyID: "external"))
        #expect(try retained.config().configID == initialID)
        let app = try await buildApplication(usecaseStore: store, privacyPassState: state)
        try await app.test(.live) { connection in
            var client = Client(connection: connection, platform: platform, userToken: "test-external-bearer")
            let result = try await client.request(keyword: "common")
            #expect(result == "A")
        }
    }
}
