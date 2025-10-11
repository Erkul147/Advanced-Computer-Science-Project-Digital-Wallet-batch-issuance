
import java.util.ArrayList;


public class MerkleTree {
    ArrayList<ArrayList<Node>> tree = new ArrayList<>();

    public MerkleTree(String[] attributes) {
        createMerkleTree(attributes);
    }
    
    public void createMerkleTree(String[] attributes) {
        int height = 0;
        byte[][] salts = new byte[attributes.length][20];
        ArrayList<Node> level = new ArrayList<>();
        Node node;

        for (int i = 0; i < attributes.length; i++) {
            salts[i] = CryptoTools.generateSalt(20);
            
            node = new Node(null, height, i, null, null);
            level.add(node);

        }
        if (attributes.length % 2 != 0) {
            node = new Node(null, height, attributes.length, null, null);
            level.add(node);
        }
        tree.add(level);

        int len = level.size() / 2;
        ArrayList<Node> lastLevel;

        while (len >= 1) { 
            lastLevel = level;
            level = new ArrayList<>();
            height++;
            int childCounter = 0;
            
            for (int i = 0; i < len; i++) {
                Node child1 = lastLevel.get(childCounter++);
                Node child2 = lastLevel.get(childCounter++);
                Node[] children = new Node[] {
                    child1,
                    child2
                };

                node = new Node(null, height, i, null, children);

                child1.parent = node;
                child2.parent = node;
                
            }



        }
        

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