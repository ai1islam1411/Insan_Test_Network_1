/** Insan Test Network 1 By Insan Technology Company Eng. AbdAllah Islam Bin ElHassan /

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>

#define WALLET_SIZE 10000000
#define BLOCK_SIZE 1000

typedef struct {
    char address[34];
    double balance;
} wallet;

typedef struct {
    char sender[34];
    char receiver[34];
    double amount;
    double fee;
    char signature[65];
} transaction;

typedef struct {
    int index;
    char previousHash[65];
    time_t timestamp;
    transaction transactions[BLOCK_SIZE];
    char blockHash[65];
} block;

typedef struct {
    char name[50];
    char symbol[10];
    double totalSupply;
    double fee;
    double zakat;
    wallet wallets[WALLET_SIZE];
    block* head;
} currency;

int searchWallet(wallet* wallets, char* address, int size) {
    for (int i = 0; i < size; i++) {
        if (strcmp(wallets[i].address, address) == 0) {
            return i;
        }
    }
    return -1;
}

void calculateHash(block* b) {
    char info[200];
    snprintf(info, 200, "%d%s%s%.8f%.8f", b->index, b->previousHash, b->transactions[0].sender, b->transactions[0].amount, b->transactions[0].fee);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, info, strlen(info));
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    for (int i = 0; i < md_len; i++) {
        sprintf(&b->blockHash[i * 2], "%02x", md_value[i]);
    }
}

void addBlock(currency* c, block* b) {
    b->index = c->totalSupply / BLOCK_SIZE;
    c->totalSupply += BLOCK_SIZE;
    b->timestamp = time(NULL);
    block* currentBlock = c->head;
    while (currentBlock->index + 1 != b->index) {
        currentBlock = currentBlock->nextBlock;
    }
    currentBlock->nextBlock = b;
    b->previousBlock = currentBlock;
    calculateHash(b);
}

void printBlockchain(currency* c) {
    block* currentBlock = c->head;
    while (currentBlock != NULL) {
        printf("Block %d\n", currentBlock->index);
        printf("Timestamp: %s", ctime(&currentBlock->timestamp));
        printf("Previous Hash: %s\n", currentBlock->previousHash);
        printf("Block Hash: %s\n", currentBlock->blockHash);
        for (int i = 0; i < BLOCK_SIZE; i++) {
            if (currentBlock->transactions[i].sender[0] != '\0') {
                printf("Transaction %d\n", i + 1);
                printf("Sender: %s\n", currentBlock->transactions[i].sender);
                printf("Receiver: %s\n", currentBlock->transactions[i].receiver);
                printf("Amount: %.8f INSAN\n", currentBlock->transactions[i].amount);
                printf("Fee: %.8f INSAN\n", currentBlock->transactions[i].fee);
                printf("Signature: %s\n", currentBlock->transactions[i].signature);
            }
        }
        printf("\n");
        currentBlock = currentBlock->nextBlock;
    }
}

int transfer(currency* c, char* sender, char* receiver, double amount, char* message) {
    // Check if sender and receiver wallets exist
    int senderIndex = searchWallet(c->wallets, sender, WALLET_SIZE);
    if (senderIndex == -1) {
        printf("Sender wallet not found\n");
        return -1;
    }
    int receiverIndex = searchWallet(c->wallets, receiver, WALLET_SIZE);
    if (receiverIndex == -1) {
        printf("Receiver wallet not found\n");
        return -1;
    }

    // Check if sender has sufficient balance
    if (c->wallets[senderIndex].balance < amount + c->fee) {
        printf("Insufficient balance\n");
        return -1;
    }

    // Create new transaction
    transaction newTransaction;
    strcpy(newTransaction.sender, sender);
    strcpy(newTransaction.receiver, receiver);
    newTransaction.amount = amount;
    newTransaction.fee = c->fee;
    char info[200];
    snprintf(info, 200, "%s%s%.8f%.8f%s", sender, receiver, amount, c->fee, message);
    unsigned char signature[65];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, c->wallets[senderIndex].address, strlen(c->wallets[senderIndex].address));
    EVP_DigestUpdate(mdctx, info, strlen(info));
    EVP_DigestFinal_ex(mdctx, signature, NULL);
    EVP_MD_CTX_free(mdctx);
    for (int i = 0; i < 32; i++) {
        sprintf(&newTransaction.signature[i * 2], "%02x", signature[i]);
    }

    // Add transaction to the blockchain
    int currentIndex = c->totalSupply - 1;
    block* currentBlock = c->head;
    while (currentBlock->index * BLOCK_SIZE <= currentIndex) {
        currentBlock = currentBlock->nextBlock;
    }
    int transactionIndex = currentIndex % BLOCK_SIZE;
    currentBlock->transactions[transactionIndex] = newTransaction;
    calculateHash(currentBlock);

    // Update wallet balances
    c->wallets[senderIndex].balance -= amount + c->fee;
    c->wallets[receiverIndex].balance += amount;

    // Check if zakat is due
    double zakatThreshold = c->totalSupply * 0.025;
    if (c->zakat < zakatThreshold) {
        double zakatAmount = zakatThreshold - c->zakat;
        c->zakat += zakatAmount;
        printf("Zakat of %.8f INSAN has been deducted for the right of Allah (SWT) in His wealth\n", zakatAmount);
    }

    return 0;
}

int main() {
    currency INSAN;
    strcpy(INSAN.name, "Insanchain");
    strcpy(INSAN.symbol, "INSAN");
    INSAN.totalSupply = BLOCK_SIZE;
    INSAN.fee = 0.00000000;
    INSAN.zakat = 0;
    block* genesisBlock = (block*) malloc(sizeof(block));
    genesisBlock->index = 0;
    strcpy(genesisBlock->previousHash, "");
    genesisBlock->timestamp = time(NULL);
    for (int i = 0; i < BLOCK_SIZE; i++) {
        genesisBlock->transactions[i].sender[0] = '\0';
    }
    calculateHash(genesisBlock);
    INSAN.head = genesisBlock;
    wallet engineerWallet;
    strcpy(engineerWallet.address, "Abdallah Islam Bin ElHassan");
    engineerWallet.balance = 1000000;
    INSAN.wallets[0] = engineerWallet;
    wallet companyWallet;
    strcpy(companyWallet.address, "Insan Technology");
    companyWallet.balance = 0;
    INSAN.wallets[1] = companyWallet;
    transfer(&INSAN, "Abdallah Islam Bin ElHassan", "Insan Technology", 1000, "Initial transfer");
    printBlockchain(&INSAN);
    return 0;
}
