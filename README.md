# Merkle-Tree

#### Contributes

* Tomer Shay
* Roei Gida

Implementation of Merkle Tree that combines RSA encryption with a signature on the tree root and verification of the signature. In addition, an implementation of Sparse Merkle Tree.

1. [General](#General)
    - [Background](#background)
    - [Running Instructions](https://github.com/tomershay100/Merkle-Tree/blob/main/README.md#running-instructions)
2. [Dependencies](#dependencies)
3. [Installation](#installation)

## General

### Background
Implementation of ```Merkle Tree``` in python, which allows you to add leaves to the tree, calculate the ```root of the tree``` and create ```Proof Of Inclusion``` on a leaf. In addition, the ```Proof Of Inclusion``` can be checked.

A private and public key can be created using the ```RSA algorithm```. And using a private key to sign the current tree root as well as verify the correctness of the signature.

In addition, implementation of ```Sparse Merkle Tree``` - Merkel Tree which all leaves have a value of 0 or 1. You can mark a leaf as 1, calculate the root of the tree, create ```Proof Of Inclusion``` and check its correctness. The idea of the Sparse Tree is to save time calculating the whole Tree (or the root). In fact, many sub-trees in the tree have the same values and therefore only a short and quick calculation is needed.

### Running Instructions

The code is built as a switch and case, where each case is responsible for a different part:

**case 1:**
> Input: String (the string will be inserted into a value of a leaf in the tree).

**case 2:**
> Calculate the current tree root (without input).
> Output: The tree root in hexadedimal encoding.

**case 3:**
> Input: Leaf index (leaf indexes start from the leftmost leaf and have a value of 0).
> Output: Proof of inclution of the leaf.

**case 4**
> Input: Leaf value and proof of inclution of the leaf.
> Output: True if the proof is correct, otherwise False.

**case 5**
> Output: Private and Public Key (RSA).

**case 6**
> Input: Private key.
> Output: Signature of the tree root.

**case 7**
> Input: Public key, signature of tree root, tree root.
> Output: True if the signature is correct, otherwise False.

**case 8**
> Input: Leaf index (leaf indexes start from the leftmost leaf and have a value of 0).
> Convert the leaf value to 1.

**case 9**
> Calculate the current tree root (without input).
> Output: The tree root in hexadedimal encoding.

**case 10**
> Input: Leaf index (leaf indexes start from the leftmost leaf and have a value of 0).
> Output: Proof of inclution of the leaf.

**case 11**
> Input: Leaf index, Leaf value and proof of inclution of the leaf.
> Output: True if the proof is correct, otherwise False.

## Installation

1. Open the terminal
2. Clone the project by:
	```
	$ git clone https://github.com/tomershay100/Merkle-Tree.git
	```	
3. Run the receiver client:
	```
	$ python3 main.py
	 ```
4. You can now insert the switch and case inputs.

