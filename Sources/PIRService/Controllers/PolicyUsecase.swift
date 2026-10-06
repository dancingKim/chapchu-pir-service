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
import HomomorphicEncryptionProtobuf
import PrivateInformationRetrievalProtobuf

struct PolicyDataset: Sendable {
    let policyID: String
    let name: String
    let usecase: PolicyUsecase
    let versionCount: Int
}

/// Dataset identity is distinct from encryption-parameter identity. A cached query
/// names its immutable dataset revision even when two datasets share parameters.
struct PolicyUsecase: Usecase {
    let base: any Usecase
    let revision: String
    let contentIdentity: Data
    private let configurationID: Data

    init(base: any Usecase, policyID: String, name: String, revision: String,
         artifactDigest: Data, bloomDigest: Data) throws
    {
        guard !policyID.isEmpty, !name.isEmpty, !revision.isEmpty,
              artifactDigest.count == 32, bloomDigest.count == 32 else { throw PolicyConfigurationError.invalid }
        self.base = base
        self.revision = revision
        self.contentIdentity = try Self.digest([artifactDigest, bloomDigest, base.config().configID])
        self.configurationID = Self.digest([Data("chapchu-policy-v1".utf8), Data(policyID.utf8),
                                            Data(name.utf8), Data(revision.utf8), contentIdentity])
    }

    static func digest(_ fields: [Data]) -> Data {
        var hash = SHA256()
        for field in fields {
            var count = UInt64(field.count).bigEndian
            withUnsafeBytes(of: &count) { hash.update(data: Data($0)) }
            hash.update(data: field)
        }
        return Data(hash.finalize())
    }

    func config() throws -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Config {
        var config = try base.config()
        config.configID = configurationID
        return config
    }

    func evaluationKeyConfig() throws -> Apple_SwiftHomomorphicEncryption_V1_EvaluationKeyConfig {
        try base.evaluationKeyConfig()
    }

    func process(request: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Request,
                 evaluationKey: Apple_SwiftHomomorphicEncryption_Api_Shared_V1_EvaluationKey) async throws
        -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response
    {
        try await base.process(request: request, evaluationKey: evaluationKey)
    }

    func processOprf(request: Apple_SwiftHomomorphicEncryption_Api_Pir_V1_OPRFRequest) async throws
        -> Apple_SwiftHomomorphicEncryption_Api_Pir_V1_Response
    {
        try await base.processOprf(request: request)
    }
}
