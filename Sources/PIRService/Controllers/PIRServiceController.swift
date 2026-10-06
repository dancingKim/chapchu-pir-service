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

import Foundation
import HomomorphicEncryptionProtobuf
import Hummingbird
import HummingbirdCompression
import PrivateInformationRetrievalProtobuf
import Util

struct PIRServiceController {
    let usecases: UsecaseStore
    let evaluationKeyStore: PersistDriver
    var privacyPassState: PrivacyPassState?

    static func persistKey(user: UserIdentifier, configHash: Data, policyID: String = "") -> String {
        let base = "\(user.identifier)/\(configHash.base64EncodedString())"
        return policyID.isEmpty ? base : "policy/" + PolicyUsecase.digest([
            Data(policyID.utf8),
            Data(user.identifier.utf8),
            configHash,
        ]).base64EncodedString()
    }

    private func requireSupportedPolicyPlatform(_ context: AppContext) throws {
        if !context.policyID.isEmpty {
            guard context.platform?.osType == .iOS, context.platform?.osVersion.major == 26 else {
                throw HTTPError(.notImplemented, message: "Policy routing supports iOS 26 only")
            }
        }
    }

    func addRoutes(to group: RouterGroup<AppContext>) {
        group.add(middleware: ExtractUserIdentifierMiddleware())
            .add(middleware: ExtractPlatformMiddleware())
            .post("/key", use: key)
            .post("/queries", use: queries)
            // only `config` uses response compression, since the key and queries are not compressible.
            .add(middleware: ResponseCompressionMiddleware())
            .post("/config", use: config)
    }

    func addUnauthRoutes(to group: RouterGroup<AppContext>) {
        group
            .add(middleware: ResponseCompressionMiddleware())
            .get("/config", use: getConfig)
    }

    @Sendable
    func key(_ request: Request, context: AppContext) async throws -> Response {
        try requireSupportedPolicyPlatform(context)
        let evaluationKeys = try await request.decodeProto(
            as: Apple_SwiftHomomorphicEncryption_Api_Shared_V1_EvaluationKeys.self,
            context: context)
        for evaluationKey in evaluationKeys.keys {
            guard evaluationKey.hasMetadata, evaluationKey.hasEvaluationKey else {
                throw HTTPError(.badRequest, message: "Evaluation key has unset fields")
            }

            if !context.policyID.isEmpty,
               try await !usecases.acceptsKey(evaluationKey.metadata.identifier, policyID: context.policyID)
            {
                throw HTTPError(.badRequest, message: "Unknown evaluation key configuration")
            }
            let key = Self.persistKey(
                user: context.userIdentifier,
                configHash: evaluationKey.metadata.identifier,
                policyID: context.policyID)
            try await evaluationKeyStore.set(key: key, value: Protobuf(evaluationKey))
        }
        return .init(status: .ok)
    }

    @Sendable
    func config(_ request: Request, context: AppContext) async throws -> some ResponseGenerator {
        try requireSupportedPolicyPlatform(context)
        let configRequest = try await request.decodeProto(
            as: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigRequest.self,
            context: context)
        guard Set(configRequest.usecases).count == configRequest.usecases.count else {
            throw HTTPError(.badRequest, message: "Duplicate usecase names")
        }
        let requestedUsecases = if configRequest.usecases.isEmpty {
            await usecases.getAll(policyID: context.policyID)
        } else {
            await usecases.get(names: configRequest.usecases, policyID: context.policyID)
        }

        guard configRequest.existingConfigIds.isEmpty ||
            configRequest.existingConfigIds.count == configRequest.usecases.count
        else {
            throw HTTPError(.badRequest, message: """
                Invalid existingConfigIds count \(configRequest.existingConfigIds.count). \
                Expected 0 or \(configRequest.usecases.count).
                """)
        }

        guard configRequest.usecases.isEmpty ||
            configRequest.usecases.count == requestedUsecases.count
        else {
            throw await HTTPError(.notFound, message: """
                One or more usecases not found. Requested usecases: \(configRequest.usecases).
                Usecases available on the server: \(usecases.getAll(policyID: context.policyID).keys).
                """)
        }

        let usecaseNames = configRequest.usecases.isEmpty ? requestedUsecases.keys.sorted() : configRequest.usecases
        let existingConfigIds = configRequest.existingConfigIds.isEmpty ? Array(
            repeating: Data(),
            count: requestedUsecases.count) : configRequest.existingConfigIds
        var configs = [String: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config]()
        for (usecaseName, configId) in zip(usecaseNames, existingConfigIds) {
            if let usecase = requestedUsecases[usecaseName] {
                var config = try usecase.config(existingConfigId: Array(configId))
                if let platform = context.platform {
                    try config.makeCompatible(with: platform)
                }
                configs[usecaseName] = config
            }
        }

        let keyConfigs = try requestedUsecases.values.map { try $0.evaluationKeyConfig() }
        let keyStatusesSequence = keyConfigs.async.map { keyConfig in
            let keyConfigHash = try keyConfig.sha256()
            let key = Self.persistKey(
                user: context.userIdentifier,
                configHash: keyConfigHash,
                policyID: context.policyID)
            let storedEvaluationKey = try await evaluationKeyStore.get(
                key: key,
                as: Protobuf<Apple_SwiftHomomorphicEncryption_Api_Shared_V1_EvaluationKey>.self)
            return Apple_SwiftHomomorphicEncryption_Api_Shared_V1_KeyStatus.with { keyStatus in
                // A timestamp of 0 indicates the evaluation key does not exist on the server
                keyStatus.timestamp = storedEvaluationKey?.message.metadata.timestamp ?? 0
                keyStatus.keyConfig = keyConfig
            }
        }

        let keyStatuses: [Apple_SwiftHomomorphicEncryption_Api_Shared_V1_KeyStatus] =
            try await .init(keyStatusesSequence)
        return Protobuf(Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigResponse.with { configResponse in
            configResponse.configs = configs
            configResponse.keyInfo = keyStatuses
        })
    }

    @Sendable
    func getConfig(_: Request, context: AppContext) async throws -> some ResponseGenerator {
        guard await privacyPassState?.policyIsolation != true else {
            throw HTTPError(.notImplemented, message: "Anonymous configuration is unavailable for isolated policies")
        }
        let allUsecases = await usecases.getAll(policyID: context.policyID)
        let configs = try Dictionary(uniqueKeysWithValues: allUsecases.map { name, usecase in
            try (name, usecase.config(existingConfigId: []))
        })
        let evaluationKeyStatuses = try allUsecases.values.map { usecase in
            try Apple_SwiftHomomorphicEncryption_Api_Shared_V1_KeyStatus.with { eks in
                eks.timestamp = 0
                eks.keyConfig = try usecase.evaluationKeyConfig()
            }
        }
        return Protobuf(Apple_SwiftHomomorphicEncryption_Api_Pir_V1_ConfigResponse.with { configResponse in
            configResponse.configs = configs
            configResponse.keyInfo = evaluationKeyStatuses
        })
    }

    @Sendable
    func queries(_ request: Request, context: AppContext) async throws -> some ResponseGenerator {
        try requireSupportedPolicyPlatform(context)
        let startTime = Date.now
        let requests = try await request.decodeProto(
            as: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Requests.self,
            context: context)

        defer {
            let duration = Date.now.timeIntervalSince(startTime)
            context.logger.info("PIR query completed", metadata: ["durationMs": .stringConvertible(duration * 1000)])
        }

        let responsesSequence = requests.requests.async.map { request in // swiftlint:disable:this closure_body_length
            switch request.request {
            case let .oprfRequest(oprfRequest):
                guard let usecase = await usecases.get(name: request.usecase, policyID: context.policyID) else {
                    throw HTTPError(.badRequest, message: "Unknown usecase: \(request.usecase)")
                }
                return try await usecase.processOprf(request: oprfRequest)
            case .pirRequest:
                var evaluationKey: Apple_SwiftHomomorphicEncryption_Api_Shared_V1_EvaluationKey?
                if request.pirRequest.hasEvaluationKey {
                    evaluationKey = request.pirRequest.evaluationKey
                } else {
                    let evaluationKeyConfigHash = request.pirRequest.evaluationKeyMetadata.identifier
                    let evaluationKeyStoreKey = Self.persistKey(
                        user: context.userIdentifier,
                        configHash: evaluationKeyConfigHash, policyID: context.policyID)
                    evaluationKey = try await evaluationKeyStore.get(
                        key: evaluationKeyStoreKey,
                        as: Protobuf<Apple_SwiftHomomorphicEncryption_Api_Shared_V1_EvaluationKey>.self)?.message
                }
                guard let evaluationKey else {
                    throw HTTPError(.badRequest, message: "Evaluation key not found")
                }
                let configId = Array(request.pirRequest.configurationHash)
                guard let usecase = await usecases.get(
                    name: request.usecase,
                    configId: configId, policyID: context.policyID)
                else {
                    if await (usecases.get(name: request.usecase, policyID: context.policyID)) != nil {
                        throw HTTPError(
                            .gone,
                            message: "Configuration id: \(configId) is not available for usecase \(request.usecase).")
                    }
                    throw HTTPError(.badRequest, message: "Unknown usecase: \(request.usecase)")
                }
                if !context.policyID.isEmpty,
                   try evaluationKey.metadata.identifier != usecase.evaluationKeyConfig().sha256()
                {
                    throw HTTPError(.badRequest, message: "Evaluation key configuration mismatch")
                }
                return try await usecase.process(request: request, evaluationKey: evaluationKey)
            case .none:
                throw HTTPError(.badRequest, message: "Unknown request type.")
            }
        }
        let responses: [Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response] = try await .init(responsesSequence)
        return Protobuf(Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Responses.with { apiResponses in
            apiResponses.responses = responses
        })
    }
}
