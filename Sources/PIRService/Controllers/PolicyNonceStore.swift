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

import Foundation
import PrivacyPass
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum PolicyConfigurationError: Error { case invalid, journalUnavailable, replay }

/// Single-process durable redemption journal. store() is the atomic second check:
/// upstream Verifier awaits between contains() and store(). Never prune with a live issuer key.
actor PolicyNonceStore: NonceStoring {
    private var nonces: Set<Data> = []
    private let file: FileHandle?
    nonisolated let path: String?
    private var failed = false

    init(path: String? = nil, binding: Data = Data(repeating: 0, count: 32)) throws {
        self.path = path
        guard binding.count == 32 else { throw PolicyConfigurationError.invalid }
        guard let path else {
            self.file = nil
            return
        }
        // O_CREAT without O_TRUNC prevents a competing first startup from erasing
        // the active process's journal before discovering its exclusive lock.
        let descriptor = open(path, O_RDWR | O_CREAT | O_NOFOLLOW, mode_t(0o600))
        guard descriptor >= 0 else { throw PolicyConfigurationError.journalUnavailable }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var attributes = stat()
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0, fstat(descriptor, &attributes) == 0,
              attributes.st_mode & 0o077 == 0,
              attributes.st_size >= 0, attributes.st_size <= 64 * 1024 * 1024
        else {
            try? handle.close()
            throw PolicyConfigurationError.journalUnavailable
        }
        var contents = try handle.readToEnd() ?? Data()
        if contents.isEmpty {
            try handle.write(contentsOf: binding)
            try handle.synchronize()
            contents = binding
        }
        guard contents.count >= 32, contents.prefix(32) == binding, contents.count.isMultiple(of: 32) else {
            try? handle.close()
            throw PolicyConfigurationError.journalUnavailable
        }
        for offset in stride(from: 32, to: contents.count, by: 32) {
            nonces.insert(contents.subdata(in: offset..<(offset + 32)))
        }
        self.file = handle
    }

    func contains(nonce: [UInt8]) throws -> Bool {
        guard !failed else { throw PolicyConfigurationError.journalUnavailable }
        return nonces.contains(Data(nonce))
    }

    func store(nonce: [UInt8]) throws {
        guard !failed, nonce.count == 32, nonces.count < 2_097_152 else {
            throw PolicyConfigurationError.journalUnavailable
        }
        let value = Data(nonce)
        guard !nonces.contains(value) else { throw PolicyConfigurationError.replay }
        do {
            try file?.write(contentsOf: value)
            try file?.synchronize()
            nonces.insert(value)
        } catch {
            failed = true
            throw PolicyConfigurationError.journalUnavailable
        }
    }
}
