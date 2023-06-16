const { expect } = require("chai")
const { ethers } = require("hardhat")
const { MerkleTree } = require("merkletreejs")
const keccak256 = require("keccak256")

describe("Password Manager", function(){
    let contract, signer;
    beforeEach(async function(){
        let PasswordManager = await ethers.getContractFactory("PasswordManager")
        contract = await PasswordManager.deploy()
        signer = await ethers.getSigner()
    })
    describe("Public functions", function(){
        it("Adds new credentials and emits event", async function () {
            let website = "https://www.google.com"
            let username = "test"
            let password = "test"
            await expect(contract.addCredentials(website, username, password)).to.emit(
                contract,
                "added_temp_credentials"
            )
        })

        // "merkleRoot": "0xe0f5cc1881798bcd215bea94365f067fce12b6c3d429e2e1b30cc9ce2efabeb5" for "https://www.google.com", "test", "test"
        it("Approves submitted credentials", async function () {  //TODO: Fix this test
            let website = "https://www.google.com"
            let username = "test"
            let password = "test"
            await contract.addCredentials(website, username, password)
            let utf8Encode = new TextEncoder()
            let signature = await signer.signMessage(
                utf8Encode.encode("0xe0f5cc1881798bcd215bea94365f067fce12b6c3d429e2e1b30cc9ce2efabeb5")
            )
            console.log(signer)
            console.log(signature)
            await contract.approveCredentials(signature)
        })
    })
})