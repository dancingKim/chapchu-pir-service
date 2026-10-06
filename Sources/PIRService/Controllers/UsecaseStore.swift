// Copyright 2024-2025 Apple Inc. and the Swift Homomorphic Encryption project authors
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
import HomomorphicEncryption
import PrivateInformationRetrieval

actor UsecaseStore {
    typealias ConfigId = [UInt8]

    struct VersionedUsecases {
        /// Mapping from Configuration ID to usecase.
        var usecases: [ConfigId: Usecase]
        /// Configuration IDs, in order from oldest to newest.
        var configIds: [ConfigId]
        /// How many versions to store.
        var versionCount: Int

        /// Newest configuration ID.
        var latestConfigId: ConfigId? {
            configIds.last
        }

        var usecase: Usecase? {
            if let latestConfigId {
                return usecases[latestConfigId]
            }
            return nil
        }

        init(versionCount: Int) {
            self.usecases = [:]
            self.configIds = []
            self.versionCount = versionCount
        }

        mutating func add(usecase: Usecase, versionCount: Int? = nil) throws {
            let configId = try Array(usecase.config().configID)
            // make sure there are no double entries with the same configID.
            if let existingLocation = configIds.firstIndex(of: configId) {
                configIds.remove(at: existingLocation)
            }
            configIds.append(configId)
            usecases[configId] = usecase

            if let versionCount {
                self.versionCount = versionCount
            }
            trim()
        }

        /// Remove old usecases
        mutating func trim() {
            precondition(versionCount >= 0)
            while configIds.count > versionCount {
                let removedConfigID = configIds.removeFirst()
                usecases[removedConfigID] = nil
            }
        }
    }

    struct Namespace: Hashable { let policyID: String; let name: String }
    var store: [Namespace: VersionedUsecases]

    var allUsecaseNames: [String] {
        .init(store.keys.filter(\.policyID.isEmpty).map(\.name))
    }

    init() {
        self.store = [:]
    }

    func set(name: String, usecase: Usecase?, versionCount: Int = 2, policyID: String = "") throws {
        let name = Namespace(policyID: policyID, name: name)
        if let usecase {
            try store[name, default: .init(versionCount: versionCount)].add(
                usecase: usecase,
                versionCount: versionCount)
        } else {
            store[name] = nil
        }
    }

    func get(name: String, configId: ConfigId, policyID: String = "") -> Usecase? {
        store[Namespace(policyID: policyID, name: name)]?.usecases[configId]
    }

    func get(name: String, policyID: String = "") -> Usecase? {
        store[Namespace(policyID: policyID, name: name)]?.usecase
    }

    func get(names: [String], policyID: String = "") -> [String: Usecase] {
        .init(uniqueKeysWithValues: names.compactMap { name in
            guard let usecase = store[Namespace(policyID: policyID, name: name)]?.usecase else {
                return nil
            }
            return (name, usecase)
        })
    }

    func getAll(policyID: String = "") -> [String: Usecase] {
        Dictionary(uniqueKeysWithValues: store.compactMap { key, versions in
            guard key.policyID == policyID, let usecase = versions.usecase else {
                return nil
            }
            return (key.name, usecase)
        })
    }

    func acceptsKey(_ hash: Data, policyID: String) throws -> Bool {
        try store.filter { $0.key.policyID == policyID }.values.contains { versions in
            try versions.usecases.values.contains { try $0.evaluationKeyConfig().sha256() == hash }
        }
    }

    /// Build a complete snapshot first. A failed revision collision leaves every policy untouched.
    func installPolicies(_ entries: [PolicyDataset]) throws {
        var staged = store
        let names = Set(entries.map { Namespace(policyID: $0.policyID, name: $0.name) })
        staged = staged.filter { names.contains($0.key) }
        for entry in entries {
            let key = Namespace(policyID: entry.policyID, name: entry.name)
            if let previous = staged[key] {
                for old in previous.usecases.values {
                    if let old = old as? PolicyUsecase, old.revision == entry.usecase.revision,
                       old.contentIdentity != entry.usecase.contentIdentity
                    {
                        throw PolicyConfigurationError.invalid
                    }
                }
            }
            try staged[key, default: .init(versionCount: entry.versionCount)].add(
                usecase: entry.usecase, versionCount: entry.versionCount)
        }
        store = staged
    }
}
