import java.io.*;
import java.net.*;

class DNSClient {

    private static boolean isNumeric(String strNum) {
        if (strNum == null) {
            return false;
        }
        try {
            Integer d = Integer.parseInt(strNum);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }
    // Return order: [timeout, maxRetries, port, queryType, server, name]
    private static String[] getArguments(String args[]) {
        String timeout = "5";
        String maxRetries = "3";
        String port = "53";
        String queryType = "A";
        String server = null;
        String name = null;

        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-t")) {
                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing timeout value");
                    System.exit(1);
                }
                timeout = args[i];
            } else if (args[i].equals("-r")) {
                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing max retries value");
                    System.exit(1);
                }
                maxRetries = args[i];
            } else if (args[i].equals("-p")) {
                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing port value");
                    System.exit(1);
                }
                port = args[i];
            } else if (args[i].equals("-mx")) {
                queryType = "MX";
            } else if (args[i].equals("-ns")) {
                queryType = "NS";
            } else if (args[i].startsWith("@")) {
                if (args[i].substring(1).isEmpty()) {
                    System.err.println("ERROR \t Missing server address after @");
                    System.exit(1);
                }
                server = args[i].substring(1);

                i++;
                if (i >= args.length) {
                    System.err.println("ERROR \t Missing domain name after server address");
                    System.exit(1);
                }
                name = args[i];
            } else {
                System.err.println("ERROR \t Incorrect input syntax: " + args[i]);
                System.exit(1);
            }
        }

        if (server == null || name == null) {
            System.err.println("ERROR \t Missing server address or domain name");
            System.exit(1);
        }

        return new String[] { timeout, maxRetries, port, queryType, server, name };
    }

    public static void main(String args[]) throws Exception {

        String[] params = getArguments(args);

        if (!isNumeric(params[0])) {
            System.err.println("ERROR \t Timeout must be a number");
            System.exit(1);
        }
        if (!isNumeric(params[1])) {
            System.err.println("ERROR \t Max retries must be a number");
            System.exit(1);
        }
        if (!isNumeric(params[2])) {
            System.err.println("ERROR \t Port must be a number");
            System.exit(1);
        }

        int timeout    = Integer.parseInt(params[0]);
        int maxRetries = Integer.parseInt(params[1]);
        int port       = Integer.parseInt(params[2]);
        String queryType = params[3];
        String server  = params[4];
        String name    = params[5];

        // Print parsed info
        
        System.out.println("DnsClient sending request for " + name);
        System.out.println("Server: " + server);
        System.out.println("Request type: " + queryType);


        BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));

//        return reader.lines().collect(Collectors.joining("\n"));
        DatagramSocket clientSocket = new DatagramSocket();

        InetAddress IPAddress = InetAddress.getByName("localhost");

        byte[] sendData = new byte[1024];
        byte[] receiveData = new byte[1024];

        String sentence = inFromUser.readLine();
        sendData = sentence.getBytes();
        DatagramPacket sendPacket =
                new DatagramPacket(sendData, sendData.length, IPAddress, 9876);

        clientSocket.send(sendPacket);

        DatagramPacket receivePacket =
                new DatagramPacket(receiveData, receiveData.length);

        clientSocket.receive(receivePacket);

        String modifiedSentence =
                new String(receivePacket.getData());

        System.out.println("FROM SERVER:" + modifiedSentence);
        clientSocket.close();
    }
}