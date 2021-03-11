import Crypto
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto import Random
from blockchain import Blockchain
import threading
import time
import codecs
import json
import random
import sys

UTP = []
VTP = []
mined_finished = {}

def gen_key():
    private_key = RSA.generate(2048)
    return private_key, private_key.publickey()

def get_address(user):
    address = user.export_key('PEM')
    return address.decode()

def sign_transaction(message,private_key):
    digest = SHA256.new(message)
    signature = pss.new(private_key).sign(digest)
    return codecs.encode(signature,'hex').decode()

def verify_transaction(message,public_key_serial,signature):
    #print("Checking if valid signature")
    key = RSA.import_key(public_key_serial)
    digest = SHA256.new(message)
    verifier = pss.new(key)
    try:
        verifier.verify(digest,codecs.decode(signature,'hex'))
        #print("valid signature")
        return 1
    except:
        #print("invalid signature")
        return 0
# an input (a pointer to one or more prior transactions outputs),
def valid_input(transaction,chain,t_type):
    #print("Checking input")
    if len(chain) == 0:
        #print("Nothing in chain")
        return 0 # No genesis transaction, we need to start with it

    input_transaction_number = transaction['INPUT']
    output_transactions = transaction['OUTPUT'][0]
    #print("prev hash:",prev_tran_hash)

    prev_transaction = None
    if t_type == 'TRANS':
        for block in chain:
            t_transaction = block['transaction']
            #print("Number:",t_transaction['NUMBER'])
            if t_transaction['NUMBER'] == input_transaction_number:
                """
                TODO: If the transaction is invalid due to double-spending, 
                report an error and permanently discard it from the network
                """
                prev_transaction = t_transaction
                break
    elif t_type == 'MERGE':
        #print("Working on merge")
        input_deposit = {}
        current_sender = output_transactions['sender'][1]
        for t_number in input_transaction_number:
            input_deposit[t_number] = -1
        #print("MERGE = All current inputs set to -1")
        for block in chain:
            t_transaction = block['transaction']
            #print("MERGE = Getting a new transaction")
            if t_transaction['NUMBER'] in input_deposit:
                #print("MERGE = This transaction is part of input")
                t_output = t_transaction['OUTPUT'][0]
                t_recipient = t_output['recipient'][1]
                if current_sender != t_recipient:
                    #invalid transaction
                    #print("MERGE = Invalid transaction, REMOVE from UTP")
                    UTP.remove(transaction)
                    return 0
                input_deposit[t_transaction['NUMBER']] = t_output['recipient'][0]
                #print("MERGE =  Valid input")
        #print("MERGE = Getting Balance")
        balance = 0
        for key in input_deposit:
            if input_deposit[key] == -1:
                #print("MERGE = We haven't seen this input; must return INVALID inputs, KEEP in UTP")
                return 0
            else:
                balance += input_deposit[key]
        #print("MERGE = Balance:",balance)
        current_sent = output_transactions['recipient'][0]
        claim_balance = output_transactions['sender'][0]
        if claim_balance == balance and current_sent <= balance:
            #print("MERGE = Correct amount of coin being sent")
            return 1
        else:
            #print("MERGE = Sent amount is greater than balance or claiming wrong amount of coin")
            #print("MERGE = Might want to DELETE from UTP")
            return 0

    if prev_transaction == None:
        #print("We couldn't find prev. transaction")
        return 0
    prev_outputs = prev_transaction['OUTPUT'][0]
    prev_sender = prev_outputs['sender'][1]
    prev_recipient = prev_outputs['recipient'][1]
    prev_sent = prev_outputs['recipient'][0]
    prev_balance = prev_outputs['sender'][0] - prev_sent

    current_sender = output_transactions['sender'][1]
    current_recipient = output_transactions['recipient'][1]
    current_sent = output_transactions['recipient'][0]
    current_balance = output_transactions['sender'][0] - current_sent

    if prev_recipient == current_sender and current_sent <= prev_sent:
        return 1
    elif prev_sender == current_sender and current_sent <= prev_balance:
        return 1

    return 0

def add_from_VTP(chain,index):
    #Check that the length of VTP is the same as node's chain and pick the biggest one
    if len(VTP) > 0:
        try:
            block_transaction = VTP[index]
        except:
            return index
        proof = block_transaction['proof']
        if proof == 'NULL':
            chain.append(block_transaction)
            print("NULL<-{}".format(block_transaction['tid']))
            index += 1
        else:
            """
            TODO:  Nodes must support and detect forks in their chain, and remove all verified transactions from the 
            shorter branch in their chain returning them to the Unverified Transaction Pool
            """
            proof = block_transaction['proof']
            # its hash pointer correctly points to the previous transaction
            prev_hash = block_transaction['prev_transaction']
            if proof < 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF and prev_hash == chain[-1]['tid']:
                chain.append(block_transaction)
                #print('{} is adding another block'.format(name))
                print("{}<-{}".format(block_transaction['prev_transaction'],block_transaction['tid']))
                index += 1
            else:
                UTP.append(block_transaction['transaction'])
                VTP.remove(block_transaction)
    return index

def handle_join(transaction,utp_index,chain,blockchain):
    #TODO:If the transaction is invalid due to double-spending, report an error and permanently discard it from the network. 
    #If the transaction is invalid because the input doesn’t yet exist, return it to the UTP
    #checks for valid inputs HERE------
    print("JOIN-Working on the JOIN TRANSACTION")
    transaction_input = transaction['INPUT']
    transaction_output = transaction['OUTPUT']
    if len(transaction_input) != len(transaction_output):
        print("JOIN - Length does not match, REMOVing from UTP")
        UTP.remove(transaction)
        return utp_index
    
    input_deposit = {}
    for i in transaction_input:
        input_deposit[i] = 0

    for block in chain:
        temp_trans = block['transaction']
        if temp_trans['NUMBER'] in input_deposit:
            for i in range(len(transaction_input)):
                if temp_trans['NUMBER'] == transaction_input[i]:
                    #TODO: check trans type, if it's a merge, will need to get every recipient coins[ ]
                    if temp_trans['TYPE'] == 'JOIN':
                        pass
                    else:
                        prev_output = temp_trans['OUTPUT'][0]
                        prev_sender = prev_output['sender'][1] #The prev person that sent
                        prev_balance = prev_output['sender'][0] #The amount they OWN
                        prev_recipient = prev_output['recipient'][1] #The recipient of prev trans
                        prev_deposit = prev_output['recipient'][0] #The amount they recieved
                        
                        curr_output = transaction_output[i]
                        curr_sender = curr_output['sender'][1] #The sender of current trans
                        curr_balance = curr_output['sender'][0] #The amount they OWN
                        curr_recipient = curr_output['recipient'][1] #The recipient of current trans
                        curr_deposit = curr_output['recipient'][0] #The amount they are receiving 

                        if prev_sender == curr_sender:
                            temp_balance = prev_balance - prev_deposit
                            if temp_balance != curr_balance or curr_deposit > curr_balance:
                                print("JOIN-prev_sender == curr_sender ;; removing transaction bc prev balance != curr balance or amount sent is more than balance")
                                UTP.remove(transaction)
                                return utp_index
                        elif prev_recipient == curr_sender or prev_sender == curr_recipient:
                            if prev_deposit != curr_balance or curr_deposit > curr_balance: 
                                print("JOIN-prev_recip == curr_sender ;; removing transaction bc prev balance != curr balance")
                                UTP.remove(transaction)
                                return utp_index
            input_deposit[temp_trans['NUMBER']] = 1        
    for key in input_deposit:
        if input_deposit[key] == 0:
            print("JOIN ;; have not seen all inputs")
            return utp_index

    #--------Check for Valid Signatures------------------
    signature_str = (transaction['TYPE'] + str(transaction['INPUT']) + str(transaction['OUTPUT'])).encode()
    signatures = transaction['SIGNATURE']
    index = 0
    for tran in transaction_output:
        public_key = tran['sender'][1]
        signature = signatures[index]
        if verify_transaction(signature_str,public_key,signature) == 0:
            print("JOIN-signature ;;  We got invalid signatures, REMOVing transaction")
            UTP.remove(transaction)
            return utp_index
        index += 1
    # 2. Add a hash pointer to the last transaction on the Node's chain
    #Run Proof of Work:
    #print("{} is now mining".format(self.name))
    mined = 0
    nonce = None
    digest = None
    while True:
        if transaction not in UTP:
            #print("{} will no longer mine as it has been mined".format(self.name))
            mined = 0
            break
        nonce = random.randrange(sys.maxsize)
        transaction_serial = (json.dumps(transaction) + str(nonce)).encode()

        digest = int(SHA256.new(transaction_serial).hexdigest(),16)
        
        if digest < 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
            mined = 1
            break

    if mined:
        UTP.remove(transaction)
        current_hash = SHA256.new(json.dumps(transaction).encode()).hexdigest()
        prev_block = chain[-1]
        prev_hash = prev_block['tid']
        block = blockchain.new_block(transaction,current_hash,prev_hash,nonce,digest)
        VTP.append(block)
        #print("{} mined something".format(self.name))
    return utp_index


def handle_trans(transaction,utp_index,chain,blockchain,t_type):
    signature_str = (transaction['TYPE'] + str(transaction['INPUT']) + str(transaction['OUTPUT'])).encode()
    signature = transaction['SIGNATURE']
    public_key_serial = transaction['OUTPUT'][0]['sender'][1]
   
    #TODO:If the transaction is invalid due to double-spending, report an error and permanently discard it from the network. 
    #If the transaction is invalid because the input doesn’t yet exist, return it to the UTP
    if valid_input(transaction,chain,t_type) == 0:
        #Input doesn't exists yet, returning to UTP
        #grab a new transaction
        #TODO: Take care of double spending (discard from UTP)
        pass
    elif verify_transaction(signature_str,public_key_serial,signature) == 0:
        #Invalid transaction signature doesn't verify; remove from UTP
        UTP.remove(transaction)
    else:
        # 2. Add a hash pointer to the last transaction on the Node's chain
        #Run Proof of Work:
        #print("{} is now mining".format(self.name))
        mined = 0
        nonce = None
        digest = None
        while True:
            if transaction not in UTP:
                #print("{} will no longer mine as it has been mined".format(self.name))
                mined = 0
                break
            nonce = random.randrange(sys.maxsize)
            transaction_serial = (json.dumps(transaction) + str(nonce)).encode()

            digest = int(SHA256.new(transaction_serial).hexdigest(),16)
            
            if digest < 0x00000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
                mined = 1
                break

        if mined:
            UTP.remove(transaction)
            current_hash = SHA256.new(json.dumps(transaction).encode()).hexdigest()
            prev_block = chain[-1]
            prev_hash = prev_block['tid']
            block = blockchain.new_block(transaction,current_hash,prev_hash,nonce,digest)
            VTP.append(block)
            #print("{} mined something".format(self.name))
    return utp_index        

class Node(threading.Thread):
    def __init__(self,name,blockchain):
        super(Node, self).__init__()
        self.name = name
        self.blockchain = blockchain
    def run(self):
        #print("{} started!".format(self.name))
        chain = []
        utp_index = 0
        while True:
            # 1. Select at random a transaction from UTP
            utp_index = add_from_VTP(chain,utp_index)
            if len(UTP) == 0:
                print('{} is sleeping with chain length:{}'.format(self.name,len(chain)))
                cnt = 0
                for c in chain:
                    print('{}[{}]:{}'.format(self.name,cnt,c['tid']))
                    cnt += 1
                time.sleep(60)
            else:
                index = random.randrange(len(UTP))
                #print("{} getting a new transaction".format(self.name))
                transaction = UTP[index]
                public_key_serial = transaction['OUTPUT'][0]['sender'][1]
                if public_key_serial == 'genesis':
                    #create a block for this one, it is the first block
                    #print("{} Got genesis transaction".format(self.name))
                    UTP.remove(transaction)
                    current_hash = SHA256.new(json.dumps(transaction).encode()).hexdigest()
                    block = self.blockchain.new_block(transaction,current_hash,'NULL','NULL','NULL')
                    VTP.append(block)
                    utp_index = add_from_VTP(chain,utp_index)
                    continue
                #print("{} is working on {}".format(self.name,transaction['NUMBER']))
                t_type = transaction['TYPE']
                if t_type == 'TRANS' or t_type == 'MERGE':
                    utp_index = handle_trans(transaction,utp_index,chain,self.blockchain,t_type)
                elif t_type == 'JOIN':
                    handle_join(transaction,utp_index,chain,self.blockchain)
                    pass

def run_transaction():
    user = []
    for i in range(5):
        pr_key, pu_key = gen_key()
        user.append((pr_key,pu_key))
    # USER = (Private_key, Public_key)
    #creating transaction:
    alice_public_key = user[0][1]
    alice_private_key = user[0][0]
    genesis = {
        'NUMBER': "NULL",
        'TYPE': 'TRANS',
        'INPUT': 'NULL',
        'OUTPUT': [
            {
                'sender': (25,'genesis'),
                'recipient': (25,str(get_address(alice_public_key))),
            }
        ],
        'SIGNATURE': 'NULL',
    }

    UTP.append(genesis)
    #print("Added:",genesis['NUMBER'])
    
    #user 0
    bob_public_key = user[1][1]
    bob_private_key = user[1][0]
    trans_1 = {
        'NUMBER': 'NULL',
        'TYPE': 'TRANS',
        'INPUT': "NULL",
        'OUTPUT': [
            {
                'sender': (25,str(get_address(alice_public_key))), #Alice -> 10 ->Bob; Alice new = 15
                'recipient': (10,str(get_address(bob_public_key))),
            }
        ],
        'SIGNATURE': 'NULL',
    }
    signature_str = (trans_1['TYPE'] + trans_1['INPUT'] + str(trans_1['OUTPUT'])).encode()
    signature = sign_transaction(signature_str, alice_private_key)
    trans_1['SIGNATURE'] = signature
    trans_1['NUMBER'] = SHA256.new((trans_1['INPUT'] + str(trans_1['OUTPUT']) + trans_1['SIGNATURE']).encode()).hexdigest()

    UTP.append(trans_1)
    #print("Addeed:",trans_1['NUMBER'])

    david_public_key = user[2][1]
    david_private_key = user[2][0]
    #user 1
    trans_2 = {
        'NUMBER': 'NULL',
        'TYPE': 'TRANS',
        'INPUT': trans_1['NUMBER'],
        'OUTPUT': [
            {
                'sender': (10,str(get_address(bob_public_key))), #Bob -> 10 -> David; Bob new = 0
                'recipient': (10,str(get_address(david_public_key))), #David new = 10
            }
        ],
        'SIGNATURE': 'NULL',
    }
    signature_str = (trans_2['TYPE'] + trans_2['INPUT'] + str(trans_2['OUTPUT'])).encode()
    signature = sign_transaction(signature_str,bob_private_key)
    trans_2['SIGNATURE'] = signature
    trans_2['NUMBER'] = SHA256.new((trans_2['INPUT'] + str(trans_2['OUTPUT']) + trans_2['SIGNATURE']).encode()).hexdigest()

    UTP.append(trans_2)
    #print("Added:",trans_2['NUMBER'])

    trans_3 = {
        'NUMBER': 'NULL',
        'TYPE': 'TRANS',
        'INPUT': trans_1['NUMBER'],
        'OUTPUT': [
            {
                'sender': (15,str(get_address(alice_public_key))), #Alice -> 10 -> David; Alice new = 5
                'recipient': (10,str(get_address(david_public_key))), #David new = 20
            }
        ],
        'SIGNATURE': 'NULL',
    }
    signature_str = (trans_3['TYPE'] + trans_3['INPUT'] + str(trans_3['OUTPUT'])).encode()
    signature = sign_transaction(signature_str,alice_private_key)
    trans_3['SIGNATURE'] = signature
    trans_3['NUMBER'] = SHA256.new((trans_3['INPUT'] + str(trans_3['OUTPUT']) + trans_3['SIGNATURE']).encode()).hexdigest()

    UTP.append(trans_3)
    #print("Added:",trans_3['NUMBER'])

    #MERGE TRANSACTION#
    charlie_public_key = user[3][1]
    charlie_private_key = user[3][0]
    trans_4 = {
        'NUMBER': 'NULL',
        'TYPE': 'MERGE',
        'INPUT': [trans_2['NUMBER'],trans_3['NUMBER']],
        'OUTPUT': [
            {
                'sender': (20,str(get_address(david_public_key))),
                'recipient': (15,str(get_address(charlie_public_key))),
            }
        ],
        'SIGNATURE': 'NULL',
    }
    signature_str = (trans_4['TYPE'] + str(trans_4['INPUT']) + str(trans_4['OUTPUT'])).encode()
    signature = sign_transaction(signature_str,david_private_key)
    trans_4['SIGNATURE'] = signature
    trans_4['NUMBER'] = SHA256.new((str(trans_4['INPUT']) + str(trans_4['OUTPUT']) + trans_4['SIGNATURE']).encode()).hexdigest()

    UTP.append(trans_4)

    #JOIN TRANSACTION#
    echo_public_key = user[4][1]
    echo_private_key = user[4][0]
    trans_5 = {
        'NUMBER': 'NULL',
        'TYPE': 'JOIN',
        'INPUT': [trans_3['NUMBER'],trans_4['NUMBER'],trans_4['NUMBER']],
        'OUTPUT': [
            {
                'sender': (5,str(get_address(alice_public_key))),
                'recipient': (1,str(get_address(echo_public_key)))
            },
            {
                'sender': (5,str(get_address(david_public_key))),
                'recipient': (1,str(get_address(echo_public_key)))
            },
            {
                'sender': (15,str(get_address(charlie_public_key))),
                'recipient': (1,str(get_address(echo_public_key))),
            } 
        ],
        'SIGNATURE': [],
    }
    signature_str = (trans_5['TYPE'] + str(trans_5['INPUT']) + str(trans_5['OUTPUT'])).encode()
    signature = sign_transaction(signature_str,alice_private_key)
    trans_5['SIGNATURE'].append(signature)
    signature = sign_transaction(signature_str,david_private_key)
    trans_5['SIGNATURE'].append(signature)
    signature = sign_transaction(signature_str,charlie_private_key)
    trans_5['SIGNATURE'].append(signature)

    trans_5['NUMBER'] = SHA256.new((str(trans_5['INPUT']) + str(trans_5['OUTPUT']) + str(trans_5['SIGNATURE'])).encode()).hexdigest()

    UTP.append(trans_5)

    """
    TODO:   Add 4 more transactions, transer[X], join[X], and merge[X]
            Atleast one malicious transaction (e.g. a double spend)[ ], and at least one invalid transaction[ ] 
            (e.g. one that is improperly signed, transfers more coins then are possessed, disobeys the conservation of coins, etc.).
    """

def main():
    run_transaction()
    blockchain = Blockchain()
    #"""
    for i in range(10):
        myNode = Node("Node-{}".format(i),blockchain)
        myNode.start()
        time.sleep(0.9)
    #"""

if __name__ == '__main__':
    main()
"""
[{
    'transaction': {
        'NUMBER': 'NULL', 
        'TYPE': 'TRANS', 
        'INPUT': 'NULL', 
        'OUTPUT': [{
            'sender': (25, 'genesis'), 
            'recipient': (25, '-----BEGIN PUBLIC KEY-----
                \nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAneM4RurjPQeQUxso9+HZ
                \nbsB2T5imTs+/SN1Nk5YotqLwbozP0tjP81tKaIYINIHTFn7iWlzxz/Hn1zHGaMsi
                \nIxiApAf1Y49REyjig2ieOeNpPuKaiFsz5yZA6Ma6H25ey6mNJv+I9crTxSS+MTPj
                \niCuBptfgiv4gB1LIk2AaHVGREwTh6Q3dz5KQ4eIuYBMi0nIIk+zH8WkLLjP273hy
                \nPMSROCiyVzI4ZWsq7AlO7AMp4HEjZ5YYI/leFH+273/j9ZzmBdFi94klhOTAoBJq
                \n7L1IyUnrawVm6LPzMlJF12DVc295ObKp9xhHEFfskNJNw/BCYdkIVjEskp1Agthz
                \n5QIDAQAB
                \n-----END PUBLIC KEY-----')
            }], 
            'SIGNATURE': 'NULL'
    }, 
    'tid': 'c88a375bd24dbfdccbf1881531bd205d93593e7045c27dae7d9b25e40072e0e9', 
    'prev_transaction': 'NULL', 
    'nonce': 'NULL', 
    'proof': 'NULL'
}, 
{
    'transaction': {
        'NUMBER': 'e2fe9dd773f5a8ec6e65b88aaacffd441a7c7aba9167806ef0928c69714bf7d7', 
        'TYPE': 'TRANS', 
        'INPUT': ['NULL'], 
        'OUTPUT': [{
            'sender': (25, '-----BEGIN PUBLIC KEY-----
                \nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAneM4RurjPQeQUxso9+HZ
                \nbsB2T5imTs+/SN1Nk5YotqLwbozP0tjP81tKaIYINIHTFn7iWlzxz/Hn1zHGaMsi
                \nIxiApAf1Y49REyjig2ieOeNpPuKaiFsz5yZA6Ma6H25ey6mNJv+I9crTxSS+MTPj
                \niCuBptfgiv4gB1LIk2AaHVGREwTh6Q3dz5KQ4eIuYBMi0nIIk+zH8WkLLjP273hy
                \nPMSROCiyVzI4ZWsq7AlO7AMp4HEjZ5YYI/leFH+273/j9ZzmBdFi94klhOTAoBJq
                \n7L1IyUnrawVm6LPzMlJF12DVc295ObKp9xhHEFfskNJNw/BCYdkIVjEskp1Agthz
                \n5QIDAQAB
                \n-----END PUBLIC KEY-----'), 
            'recipient': (10, '-----BEGIN PUBLIC KEY-----
                \nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqhkSSax5iECo8CFT4oTJ
                \nEqw9PDCaQBpm880a7Vwl8f0q79vYcO3RCVgHiK2pcyYbb5dUp01BGc7czBJQGPbh
                \ntwQQLnXxM+sMyAI9xI92s+JvUeU0zPnug4Y5ZdN9XGNqnTO89Q+/CJShIf6/b+Kw
                \nE9zcCYQTvslZ4bdmgV5A9aQUclSltQUhnmpyiCg+Zx9G8aOOcPk0/LayOtyou9eE
                \n07iFZJn6EN2t7XCDiWROSYR2q5jBm0H90pZi7y28wrQTWbKFFZFmgekiXbG0oI4P
                \nf32Mw/FeeMWu2a9sLsWCY7cRemNDKSwbYrEKNil+QOoyZzPFJLY0xvq2kpeCxh2I
                \nxwIDAQAB
                \n-----END PUBLIC KEY-----')
            }], 
            'SIGNATURE': '7339e0baee9d5ece23a7737148c21e7596b683cbec31927201d6c09a
                c2f445f892cf7e58a49d1421c5e47edb3e0f86177dcf6f6ea8675d3dcae53968c1
                ff912105623ad3c2c0c5dde34fa03effb840591d20d49a9010a631fc9db1979fc8
                a0a4dfbcb73d34ae4d1681d6968a81bdf1e237263c4f0d8ddcb297f853b451bc3d
                26194af5b08c86ba010d5530b9de38a721c89ba7469dafa475870e8239633c5edc
                bdef16d21b0dd49173f7ab0139b0da0e6a2bec728a35297c6f2444d2a69b83d847
                87f4ce3da2e82e65a50d24d74462bb5a6dc5441044a45fa26dce3a8ae669c838b8
                64a90acc9353928f8164afc7ce319b9291d34136b0ae0fe0007b409a2a1f'
    }, 
    'tid': 'e3fe6311bddd55ba8dd20042f1b3ec59c73436149db136bed5b6e895144c5d9a', 
    'prev_transaction': 'c88a375bd24dbfdccbf1881531bd205d93593e7045c27dae7d9b25e40072e0e9', 
    'nonce': 6444059824995783269, 
    'proof': 58014355873785145148197959313513655494153467776623190677949505404886405
}, 
{
    'transaction': {
        'NUMBER': '4b4525f7df0912e8c56012ade91d9131da8dab7648810c8f2406e247c9eb57d0', 
        'TYPE': 'TRANS', 
        'INPUT': ['NULL', 'e2fe9dd773f5a8ec6e65b88aaacffd441a7c7aba9167806ef0928c69714bf7d7'], 
        'OUTPUT': [{
            'sender': (10, '-----BEGIN PUBLIC KEY-----
                \nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqhkSSax5iECo8CFT4oTJ
                \nEqw9PDCaQBpm880a7Vwl8f0q79vYcO3RCVgHiK2pcyYbb5dUp01BGc7czBJQGPbh
                \ntwQQLnXxM+sMyAI9xI92s+JvUeU0zPnug4Y5ZdN9XGNqnTO89Q+/CJShIf6/b+Kw
                \nE9zcCYQTvslZ4bdmgV5A9aQUclSltQUhnmpyiCg+Zx9G8aOOcPk0/LayOtyou9eE
                \n07iFZJn6EN2t7XCDiWROSYR2q5jBm0H90pZi7y28wrQTWbKFFZFmgekiXbG0oI4P
                \nf32Mw/FeeMWu2a9sLsWCY7cRemNDKSwbYrEKNil+QOoyZzPFJLY0xvq2kpeCxh2I
                \nxwIDAQAB
                \n-----END PUBLIC KEY-----'), 
            'recipient': (10, '-----BEGIN PUBLIC KEY-----
                \nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxdTlpMiuXELqIlq4WIwO
                \nq9UM3yHaDvzZ8YmB82lFcZYbssAQHN9Xkdl1mEApiKlgNtpwz2SildsZOIAvsTFG
                \nuRDdxcDculm8/gtWo+tcwToW1TayG0z9RKT9pD0WrNQs+4QUnbO2b7gfJr5IsxdU
                \nmlI8vDZNpzaDZYAyc2nLhlHN6xOWB/ottEwiNXmk00yedXlGYuXXgP5bGq2Gx1rG
                \nrDtnuC+Hc85YwQRV0RPQe5JtlrhbhP8dGJT2v3/lXAO0Wk7mkWh3Jk/srTK3BCjY
                \nV4OQOSizytvcqzzZKSYPjLvbX4y035W0QNogPcepcDb9nu+dXPZBTjT4SnkuP1xb
                \n/wIDAQAB
                \n-----END PUBLIC KEY-----')
            }], 
            'SIGNATURE': '100f6ed7c95c47d61fccf95fdfdf45381c91368e1490d7518576b1d9
                1f0c6f9efdf8a58b94f7cf6e6d4ba5effaeaa90236e7766aace8e118a2fd4169fc
                29538a2af0b3a9645ad326470b522ded02057fa11c745f3e41717da05d5d2730e1
                dbb19c396f7bd7f0b52a1ec1722ea3b3305c760c146d30f8ebd8a5367f0419805f
                db8d71dfab0bc5de3bf106da67e3de74d3ee3876a72e773381f3273040e3c1837f
                f06cc4382eb4dbcf3e8a4fc2b1fcd11cb4635831fffb54c70cfd478993ed138073
                14fdb5413c3fc3ea0146944bcc34c230f5bb9df3470f809cadeed504d3046f1208
                60e152ff74c1a2738c505f2c2127745101b5cc0afe580027c9344076befb'
    }, 
    'tid': 'b09d7f2081fc98d3d54bcb6e062dd7f1f150d554f287cb7f1e7c55a953b12153', 
    'prev_transaction': 'e3fe6311bddd55ba8dd20042f1b3ec59c73436149db136bed5b6e895144c5d9a', 
    'nonce': 3423088958377838589, 
    'proof': 69979512588819471986242818937081346447646348601362675440253978063003798
}]

Node-5:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-5:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-5:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-4:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-4:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-4:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-9:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-9:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-9:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-3:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-3:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-3:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-6:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-6:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-6:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-7:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-7:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-7:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-1:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-1:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-1:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-8:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-8:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-8:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-2:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-2:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-2:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a

Node-0:4d0096e6e079ea3712b9214044a1e3f6ed6159acb02185e7cbde476bd7922ce1
Node-0:dce692d9f7c6ae888eeacbee8fdd8f7b3d3cf894241f1f474f15a49cafeac535
Node-0:38c3e577f43a77db8d59b275e3a8c0d6820e50574e168499d6c108574a76417a
"""