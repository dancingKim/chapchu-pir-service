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
import Hummingbird
import PrivacyPass

struct PrivacyPassController {
    let state: PrivacyPassState

    func addRoutes(to group: RouterGroup<AppContext>) {
        group.get("/.well-known/private-token-issuer-directory", use: tokenIssuerDirectory)
        group.get("/token-key-for-user-token", use: tokenKeyForUserToken)
        group.post("/issue", use: issueToken)
    }

    func authenticatedIssuer(request: Request) async throws -> PrivacyPass.Issuer {
        guard let token = request.headers.bearerToken, let issuer = await state.issuer(for: token) else {
            throw HTTPError(.unauthorized, message: "User token is unauthorized")
        }
        return issuer
    }

    @Sendable
    func tokenIssuerDirectory(request _: Request, context _: AppContext) async throws -> TokenIssuerDirectory {
        let keys = try await state.directoryIssuers().map { issuer in
            try TokenIssuerDirectory.TokenKey(tokenType: PrivacyPass.TokenTypeBlindRSA,
                                              tokenKeyBase64Url: issuer.publicKey.spki().base64URLEncodedString(),
                                              notBefore: nil)
        }
        return TokenIssuerDirectory(issuerRequestUri: URL(string: "/issue")!, tokenKeys: keys)
    }

    @Sendable
    func tokenKeyForUserToken(request: Request, context _: AppContext) async throws -> PrivacyPass.PublicKey {
        try await authenticatedIssuer(request: request).publicKey
    }

    @Sendable
    func issueToken(request: Request, context _: AppContext) async throws -> PrivacyPass.TokenResponse {
        let issuer = try await authenticatedIssuer(request: request)
        // decode tokenRequest
        var tokenRequestByteBuffer = try await request.body.collect(upTo: PrivacyPass.TokenRequest.sizeInBytes)
        guard let tokenRequestBytes = tokenRequestByteBuffer.readBytes(length: PrivacyPass.TokenRequest.sizeInBytes)
        else {
            throw PrivacyPass.PrivacyPassError(code: .invalidTokenRequestSize)
        }
        let tokenRequest = try PrivacyPass.TokenRequest(from: tokenRequestBytes)
        return try issuer.issue(request: tokenRequest)
    }
}
