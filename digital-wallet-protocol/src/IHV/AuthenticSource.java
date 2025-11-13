package IHV;

import java.io.BufferedReader;
import java.io.FileReader;

public class AuthenticSource {
    // step 2: obtain data
    public static String[] getPID(String ID) {
        try {
            // create buffered reader that reads the csv
            BufferedReader br = new BufferedReader(new FileReader("digital-wallet-protocol/src/attributes.csv"));

            // fake query: find id
            for (String line = br.readLine(); line != null; line = br.readLine() ) {
                if  (line.contains(ID)) {
                    return line.split(",");
                }
            }
        } catch (Exception e) {
            System.err.println(e);
        }
        return null;
    }
}
