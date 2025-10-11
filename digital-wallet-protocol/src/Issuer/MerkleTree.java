package Issuer;

import Helper.CryptoTools;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;


public class MerkleTree {
    ArrayList<ArrayList<Node>> tree = new ArrayList<>();
    byte[][] salts;
    String[] attributes;


    public MerkleTree(String[] attributes) throws NoSuchAlgorithmException {
        this.attributes = attributes;
        salts = new byte[attributes.length][20];

        createMerkleTree();
    }
    
    public void createMerkleTree() throws NoSuchAlgorithmException {
        int height = 0;

        ArrayList<Node> level = new ArrayList<>();
        Node node = null;

        System.out.println("Creating salts and leafnodes");
        System.out.println("Tree level: " + height);
        for (int i = 0; i < attributes.length; i++) {
            salts[i] = CryptoTools.generateSalt(20);

            var combinedAttributeSalt = CryptoTools.combineByteArrays(attributes[i].getBytes(), salts[i]);
            var hash = CryptoTools.hash(combinedAttributeSalt);

            node = new Node(hash, height, i, null, null);
            level.add(node);

        }
        if (attributes.length % 2 != 0) { // if uneven, duplicate the last element
            System.out.println("duplicated");
            node = new Node(node.hash, node.height, node.index+1, node.parent, node.children);
            level.add(node);
        }

        tree.add(level);
        int len = level.size() / 2;
        ArrayList<Node> lastLevel;

        System.out.println("Creating rest of tree");
        while (len >= 1) {

            lastLevel = level;
            level = new ArrayList<>();

            height++;
            System.out.println("Tree level: " + height);

            int childCounter = 0;
            
            for (int i = 0; i < len; i++) {
                Node child1 = lastLevel.get(childCounter++);
                Node child2 = lastLevel.get(childCounter++);
                Node[] children = new Node[] {
                    child1,
                    child2
                };

                var childrenHashCombined = CryptoTools.combineByteArrays(child1.hash, child2.hash);
                var hash = CryptoTools.hash(childrenHashCombined);

                node = new Node(hash, height, i, null, children);

                child1.parent = node;
                child2.parent = node;
                level.add(node);
            }

            if (len != 1 && len % 2 != 0) { // if uneven, duplicate the last element
                System.out.println("duplicated");
                node = new Node(node.hash, node.height, node.index+1, node.parent, node.children);
                level.add(node);
            }

            tree.add(level);
            len = level.size() / 2;
        }
        System.out.println("done");
    }


}

class Node {
    Node parent;
    Node[] children;
    byte[] hash;
    int index;
    int height;

    public Node(byte[] hash, int height, int index, Node parent, Node[] children) {
        this.hash = hash;
        this.height = height;
        this.index = index;
        this.parent = parent;
        this.children = children;
    }
    
}