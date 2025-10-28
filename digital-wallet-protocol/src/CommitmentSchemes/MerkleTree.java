package CommitmentSchemes;

import Helper.CryptoTools;
import DataObjects.InclusionPath;

import java.util.ArrayList;
import java.util.Arrays;


public class MerkleTree {
    public ArrayList<ArrayList<Node>> tree = new ArrayList<>();
    public byte[][] salts;
    public String[] attributes;
    public Node root;


    public MerkleTree(String[] attributes) {
        this.attributes = attributes;
        salts = new byte[attributes.length][20];
        createMerkleTree();
    }
    
    private void createMerkleTree() {
        int height = 0; // leaf nodes start at height 0

        // level list will be used for "current level"
        ArrayList<Node> level = new ArrayList<>();

        // node will be used for "current node"
        Node node = null;

        // create the leaf nodes
        for (int i = 0; i < attributes.length; i++) {
            // generate a new salt for each leaf node
            salts[i] = CryptoTools.generateSalt(20);

            // combine the attribute with the salt and has them together
            var combinedAttributeSalt = CryptoTools.combineByteArrays(attributes[i].getBytes(), salts[i]);
            var hash = CryptoTools.hashSHA256(combinedAttributeSalt);


            // instantiate a new node and add it to the level
            node = new Node(hash, height, i, null, null);
            level.add(node);

        }
        if (attributes.length % 2 != 0) { // if uneven, duplicate the last element
            node = new Node(node.hash, node.height, node.index+1, node.parent, node.children);
            level.add(node);
        }

        // add the leaf nodes to the tree
        tree.add(level);

        // half the length of the current level to get the size of the next level
        int len = level.size() / 2;
        ArrayList<Node> lastLevel; // define last level to store the "children" of the current level

        // loop to create the internal and root nodes
        while (len >= 1) {

            // update lastlevel and level
            lastLevel = level;
            level = new ArrayList<>();

            // increment height
            height++;

            // each node will have 2 children, start at child 0
            int childCounter = 0;
            
            for (int i = 0; i < len; i++) {
                // find the children of the current node
                Node child1 = lastLevel.get(childCounter++);
                Node child2 = lastLevel.get(childCounter++);

                Node[] children = new Node[] {
                    child1,
                    child2
                };

                // combine the hash of the children
                var childrenHashCombined = CryptoTools.combineByteArrays(child1.hash, child2.hash);
                var hash = CryptoTools.hashSHA256(childrenHashCombined);

                // create the "current node"
                node = new Node(hash, height, i, null, children);

                // set the current node as the children's parent and add it to the level
                child1.parent = node;
                child2.parent = node;
                level.add(node);
            }
            if (len != 1 && len % 2 != 0) { // if uneven, duplicate the last element
                node = new Node(node.hash, node.height, node.index+1, node.parent, node.children);
                level.add(node);
            }

            // add the level to the tree and half the size
            tree.add(level);
            len = level.size() / 2;
        }

        // when we are out of the while loop, the root has been found, which would be the last node created
        root = node;
    }

    // generate inclusion paths needed to compute the root of a merkle tree from a given index
    public InclusionPath generateInclusionPath(int index) {

        // find the starting node
        Node currentNode = tree.getFirst().get(index);

        // instantiate an inclusion path object
        InclusionPath path = new InclusionPath();

        System.out.println("Generating inclusion path for index: " + index);
        System.out.println("path: ");

        while(currentNode.parent != null) {

            // find parent of the current node
            var parent = currentNode.parent;

            // check if sibling of the current node is child1(left) or child2(right)
            var siblingIsLeft = (parent.children[0] != currentNode);

            // find sibling node's hash
            var siblingHash = (siblingIsLeft) ? parent.children[0].hash : parent.children[1].hash;

            // add directional information and the hash of the sibling
            path.addPath(siblingHash, siblingIsLeft);
            System.out.println("Sibling hash: " + Arrays.toString(siblingHash) + ", left: " + siblingIsLeft);
            currentNode = parent;
        }

        return path;
    }

}


