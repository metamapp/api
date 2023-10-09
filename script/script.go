// AUTOGENERATED. DO NOT EDIT.

// Package script defines some Cadence scripts for the core Mapp framework.
package script

// EventInfo defines a Cadence script to get details about an event.
const EventInfo = `import Mapp from 0x0000000000000001

pub fun main(addr: Address, id: UInt64): {String: AnyStruct}? {
    let acct = getAccount(addr)
    // let ref = acct.capabilities.borrow<@AnyResource{Mapp.Account}>(/public/mapp)
    let ref = acct.getCapability<&{Mapp.Account}>(/public/mapp)
    return ref.borrow()!.getItem(type: "event", id: id)
}`

// GetProfile defines a Cadence script to get a profile.
const GetProfile = `import Mapp from 0x0000000000000001

pub fun main(addr: Address): Mapp.Profile {
    let acct = getAccount(addr)
    log(acct.keys.count)
    // let ref = acct.capabilities.borrow<@AnyResource{Mapp.PublicProfile}>(/public/profile)
    let ref = acct.getCapability<&{Mapp.Account}>(/public/mapp)
    return ref.borrow()!.profile
}`

// Checkin defines a Cadence script to do a checkin.
const Checkin = `import Mapp from 0x0000000000000001

transaction(platform: String, location: String, status: String) {
    prepare(signer: AuthAccount) {
        let ctrl = signer.borrow<&Mapp.Controller>(from: /storage/mapp)
            ?? panic("Could not borrow a reference to the signer's Mapp.Controller")
        ctrl.checkin(platform: platform, location: location, status: status)
    }
}`

// CreateAccount defines a Cadence script to create an account.
const CreateAccount = `import Mapp from 0x0000000000000001

transaction(publicKey: String, about: String, name: String, image: String, tags: [String]) {
    prepare(signer: AuthAccount) {
        let acct = AuthAccount(payer: signer)
        let key = PublicKey(
            publicKey: publicKey.decodeHex(),
            signatureAlgorithm: SignatureAlgorithm.ECDSA_secp256k1,
        )
        acct.keys.add(
            publicKey: key,
            hashAlgorithm: HashAlgorithm.SHA3_256,
            weight: 1000.0,
        )
        let profile = Mapp.Profile(about: about, name: name, image: image, tags: tags)
        let ctrl <- Mapp.createController(profile: profile)
        acct.save(<- ctrl, to: /storage/mapp)
        acct.link<&{Mapp.Account}>(/public/mapp, target: /storage/mapp)
        // acct.capabilities.publish(/public/mapp)
        let bctrl = acct.borrow<&Mapp.Controller>(from: /storage/mapp)
            ?? panic("Could not borrow a reference to the Mapp.Controller")
        bctrl.updateProfile(profile: profile)
    }
}`

// CreateEvent defines a Cadence script to create an event.
const CreateEvent = `import Mapp from 0x0000000000000001

transaction(platform: String, location: String, start: String, end: String, timezone: String, title: String, description: String, tags: [String], image: String) {
    prepare(signer: AuthAccount) {
        let ctrl = signer.borrow<&Mapp.Controller>(from: /storage/mapp)
            ?? panic("Could not borrow a reference to the signer's Mapp.Controller")
        ctrl.createEvent(
            platform: platform,
            location: location,
            start: start,
            end: end,
            timezone: timezone,
            title: title,
            description: description,
            tags: tags,
            image: image)
    }
}`

// CreateExperience defines a Cadence script to create an experience.
const CreateExperience = `import Mapp from 0x0000000000000001

transaction(platform: String, location: String, title: String, description: String, tags: [String], type: String, files: [String]) {
    prepare(signer: AuthAccount) {
        let ctrl = signer.borrow<&Mapp.Controller>(from: /storage/mapp)
            ?? panic("Could not borrow a reference to the signer's Mapp.Controller")
        ctrl.createExperience(
            platform: platform,
            location: location,
            title: title,
            description: description,
            tags: tags,
            type: type,
            files: files)
    }
}`

// DeleteCheckin defines a Cadence script to delete a checkin.
const DeleteCheckin = `@deleteCheckin`

// DeleteEvent defines a Cadence script to delete an event.
const DeleteEvent = `@deleteEvent`

// DeleteExperience defines a Cadence script to delete an experience.
const DeleteExperience = `@deleteExperience`

// DeployContract defines a Cadence script to deploy a contract.
const DeployContract = `transaction(name: String, code: String, update: Bool) {
    prepare(signer: AuthAccount) {
        if update {
            signer.contracts.update__experimental(
                name: name,
                code: code.utf8
            )
        } else {
            signer.contracts.add(
                name: name,
                code: code.utf8
            )
        }
    }
}`

// RsvpEvent defines a Cadence script to rsvp an event.
const RsvpEvent = `import Mapp from 0x0000000000000001

transaction(id: UInt64, status: String) {
    prepare(signer: AuthAccount) {
        let ctrl = signer.borrow<&Mapp.Controller>(from: /storage/mapp)
            ?? panic("Could not borrow a reference to the signer's Mapp.Controller")
        ctrl.rsvpEvent(id: id, status: status)
    }
}`

// StarExperience defines a Cadence script to star an experience.
const StarExperience = `import Mapp from 0x0000000000000001

transaction(id: UInt64, status: Bool) {
    prepare(signer: AuthAccount) {
        let ctrl = signer.borrow<&Mapp.Controller>(from: /storage/mapp)
            ?? panic("Could not borrow a reference to the signer's Mapp.Controller")
        ctrl.starExperience(id: id, status: status)
    }
}`

// UpdateEvent defines a Cadence script to update an event.
const UpdateEvent = `@updateEvent`

// UpdateExperience defines a Cadence script to update an experience.
const UpdateExperience = `@updateExperience`

// UpdateProfile defines a Cadence script to update a profile.
const UpdateProfile = `import Mapp from 0x0000000000000001

transaction(about: String, name: String, image: String, tags: [String]) {
    prepare(signer: AuthAccount) {
        let ctrl = signer.borrow<&Mapp.Controller>(from: /storage/mapp)
            ?? panic("Could not borrow a reference to the signer's Mapp.Controller")
        let profile = Mapp.Profile(about: about, name: name, image: image, tags: tags)
        ctrl.updateProfile(profile: profile)
    }
}`