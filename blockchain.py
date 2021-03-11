
class Blockchain(object):
    def new_block(self,transaction,tid,previous_hash,nonce,proof):
        block = {
            'transaction': transaction,
            'tid': tid,
            'prev_transaction': previous_hash,
            'nonce': nonce,
            'proof': proof,
        }
        return block