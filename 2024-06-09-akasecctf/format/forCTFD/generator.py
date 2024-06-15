import random
import json

FLAG = "AKASEC{fake_flag}"
randomLimit = random.randint(200, 250)

def generate_args():
    args = []
    for i in range(randomLimit):
        args.append(random.randint(0, 1337))  # Random integers
        args.append(f"AKASEC{i}")  # Strings
        args.append(random.uniform(0.0, 1337.42))  # Random floats
        args.append(bool(random.getrandbits(1)))  # Random booleans
    args.append(FLAG)  # Add the FLAG once
    return args

args = generate_args()
random.shuffle(args)  # Shuffle the arguments once

# Save the arguments to a file
with open('args.json', 'w') as file:
    json.dump(args, file)
