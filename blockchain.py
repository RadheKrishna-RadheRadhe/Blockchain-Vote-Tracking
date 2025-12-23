import hashlib
import time

class Block:
    def __init__(self, voter_id, candidate, prev_hash=""):
        self.voter_hash = hashlib.sha256(voter_id.encode()).hexdigest()
        self.candidate = candidate
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.prev_hash = prev_hash
        self.block_hash = self.calculate_hash()
    
    def calculate_hash(self):
        data = self.voter_hash + self.candidate + self.timestamp + self.prev_hash
        return hashlib.sha256(data.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]
        self.voters = set()  # Track unique voters by hash
    
    def create_genesis_block(self):
        return Block("genesis", "None", "0")
    
    def get_last_block(self):
        return self.chain[-1]
    
    def add_vote(self, voter_id, candidate):
        # Hash voter ID to check uniqueness
        voter_hash = hashlib.sha256(voter_id.encode()).hexdigest()
        
        if voter_hash in self.voters:
            print("❌ Duplicate vote detected!")
            return False
        
        new_block = Block(voter_id, candidate, self.get_last_block().block_hash)
        self.chain.append(new_block)
        self.voters.add(voter_hash)
        print(f"Vote added: {candidate} at {new_block.timestamp}")
        return True
    
    def verify_chain(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]
            
            if current.block_hash != current.calculate_hash():
                return False
            if current.prev_hash != prev.block_hash:
                return False
        return True
    
    def display_chain(self):
        for block in self.chain:
            print("---- Block ----")
            print(f"Voter Hash: {block.voter_hash}")
            print(f"Candidate: {block.candidate}")
            print(f"Timestamp: {block.timestamp}")
            print(f"Prev Hash: {block.prev_hash}")
            print(f"Block Hash: {block.block_hash}\n")
