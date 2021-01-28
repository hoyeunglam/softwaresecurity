# Voting Machine

Voting Machine for Software Security.

## Getting Started

Extract the project on a machine with python3 installed.


## Deployment
To run the application:

python3 vote.py -h

```
Usage: vote --create
        Initialize vote system generating vote.state & vote.state.enc
Usage: vote --vote -p <voteId> -c <candId>
        Cast vote and return the time of the vote
Usage: vote --res
        Show results generating json files with hashed ids
Usage: vote --stats
        Show overall statistics
Usage: vote --delete
        Delete all information (securily)
``` 
## Built With

* [PyCharm](https://www.jetbrains.com/pycharm/) - PyCharm

## Authors

**Ho Yeung Lam** - Encryption and Hashing - [HoyeungLam] (https://github.com/HoyeungLam)

See also the list of [contributors](https://github.com/hoyeunglam/softwaresecurity/contributors) 
who participated in this project.

## Techniques & Encryption

Cryptography.hazmat.primitives RSA-2048 (https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa.html)

Python3 Library .hash function 





