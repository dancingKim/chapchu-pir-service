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
import PrivacyPass

struct PolicyCredential: Sendable {
    let id: String
    let bearer: String
    let issuer: PrivacyPass.Issuer
    let nonceStore: PolicyNonceStore
}

actor PrivacyPassState {
    private struct Binding: Sendable {
        let policyID: String
        let issuer: PrivacyPass.Issuer
        let verifier: PrivacyPass.Verifier<PolicyNonceStore>
    }

    private var allowList: Set<String> = []
    let issuer: PrivacyPass.Issuer
    private var bindings: [[UInt8]: Binding] = [:]
    private var bearers: [String: [UInt8]] = [:]
    private(set) var policyIsolation = false

    init() throws {
        let issuer = try PrivacyPass.Issuer(privateKey: .init())
        self.issuer = issuer
        bindings[issuer.publicKey.tokenKeyId] = try Binding(
            policyID: "", issuer: issuer,
            verifier: .init(publicKey: issuer.publicKey, nonceStore: PolicyNonceStore()))
    }

    func authenticate(userToken: String) -> Bool {
        policyIsolation ? bearers[userToken] != nil : allowList.contains(userToken)
    }

    func issuer(for userToken: String) -> PrivacyPass.Issuer? {
        if policyIsolation {
            return bearers[userToken].flatMap { bindings[$0]?.issuer }
        }
        return allowList.contains(userToken) ? issuer : nil
    }

    func directoryIssuers() -> [PrivacyPass.Issuer] {
        bindings.values.map(\.issuer)
    }

    func verify(_ token: PrivacyPass.Token) async throws -> String? {
        guard let binding = bindings[token.tokenKeyId],
              try await binding.verifier.verify(token: token)
        else {
            return nil
        }
        // Reload may revoke a binding while signature verification awaits the nonce journal.
        guard bindings[token.tokenKeyId]?.policyID == binding.policyID else {
            return nil
        }
        return binding.policyID
    }

    func nonceStore(for key: [UInt8]) -> PolicyNonceStore? {
        bindings[key]?.verifier.nonceStore
    }

    func validate(_ credentials: [PolicyCredential]) throws {
        guard !credentials.isEmpty else { throw PolicyConfigurationError.invalid }
        var ids = Set<String>(), tokens = Set<String>(), keys = Set<[UInt8]>()
        for credential in credentials {
            let key = credential.issuer.publicKey.tokenKeyId
            guard !credential.id.isEmpty, !credential.bearer.isEmpty,
                  ids.insert(credential.id).inserted, tokens.insert(credential.bearer).inserted,
                  keys.insert(key).inserted else { throw PolicyConfigurationError.invalid }
            if let old = bindings[key], old.policyID != credential.id {
                throw PolicyConfigurationError.invalid
            }
            // A stable policy key is not silently rotated or reassigned on reload.
            if let old = bindings.values.first(where: { $0.policyID == credential.id }),
               old.issuer.publicKey.tokenKeyId != key
            {
                throw PolicyConfigurationError.invalid
            }
        }
    }

    func install(_ credentials: [PolicyCredential]) {
        bindings = Dictionary(uniqueKeysWithValues: credentials.map { credential in
            let key = credential.issuer.publicKey.tokenKeyId
            let binding = bindings[key] ?? Binding(policyID: credential.id, issuer: credential.issuer,
                                                   verifier: .init(
                                                       publicKey: credential.issuer.publicKey,
                                                       nonceStore: credential.nonceStore))
            return (key, binding)
        })
        bearers = Dictionary(uniqueKeysWithValues: credentials.map { ($0.bearer, $0.issuer.publicKey.tokenKeyId) })
        allowList = []
        policyIsolation = true
    }

    func add(token: String) {
        allowList.insert(token)
    }

    func update(allowList: Set<String>) {
        self.allowList = allowList
    }
}
