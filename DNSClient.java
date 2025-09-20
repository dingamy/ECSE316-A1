
import java.net.*;
import java.util.*;
import java.io.*;

class DNSClient {

    private static final int TYPE_A = 0x0001;
    private static final int TYPE_NS = 0x0002;
    private static final int TYPE_CNAME = 0x0005; //This can be received but not queried
    private static final int TYPE_MX = 0x000f;
    private static final int CLASS_IN = 0x0001;

    // Helper class to hold query result
    private static final class QueryResult {

        final int transactionId;
        final byte[] packet;

        QueryResult(int id, byte[] pkt) {
            this.transactionId = id;
            this.packet = pkt;
        }
    }

    // Helper class to hold send result
    private static final class SendResult {

        final int transactionId;
        final byte[] response;
        final long elapsedMillis;
        final int retriesUsed;

        SendResult(int id, byte[] resp, long ms, int retries) {
            this.transactionId = id;
            this.response = resp;
            this.elapsedMillis = ms;
            this.retriesUsed = retries;
        }
    }

    // Helper function to check if a string is numeric
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

    //Helper function converting IP string into InetAddress; return null if invalid
    public static InetAddress convertToInetAddress(String ip) {
        String[] parts = ip.split("\\.");
        //IPv4 should exactly 4 parts since 32-bit 
        if (parts.length != 4) {
            return null;
        }
        //addr = [0, 0, 0, 0]
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            int part;
            try {
                part = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                return null;
            }
            // Ipv4 addr is 32-bit, each octet is 8 bits and ranges from 0-255 (2^8 = 256)
            if (part < 0 || part > 255) {
                return null;
            }
            bytes[i] = (byte) part;
        }
        try {
            return InetAddress.getByAddress(bytes);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    // Return order: [timeout, maxRetries, port, queryType, server, name]
    private static String[] getArguments(String args[]) {
        String timeout = "5";
        String maxRetries = "3";
        String port = "53";
        String queryType = "A";
        String server = null;
        String name = null;

        //Validation flag 
        Boolean isMx = false;
        Boolean isNs = false;

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
                if (isNs) {
                    System.err.println("ERROR \t Cannot set both -mx and -ns");
                    System.exit(1);
                }
                queryType = "MX";
                isMx = true;
            } else if (args[i].equals("-ns")) {
                if (isMx) {
                    System.err.println("ERROR \t Cannot set both -mx and -ns");
                    System.exit(1);
                }
                queryType = "NS";
                isNs = true;
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
        return new String[]{timeout, maxRetries, port, queryType, server, name};
    }

    // Convert query type string to its corresponding integer value
    private static int qtypeFromString(String s) {
        if (s == null) {
            return TYPE_A;
        }
        switch (s.toUpperCase(Locale.ROOT)) {
            case "A":
                return TYPE_A;
            case "NS":
                return TYPE_NS;
            case "MX":
                return TYPE_MX;
            default:
                return TYPE_A; // default to A if unknown
        }
    }

    // Encode domain name into DNS format
    private static byte[] encodeName(String name) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        String[] labels = name.split("\\.");
        for (String label : labels) {
            // Labels can only be at most 63 octets long
            if (label.length() == 0 || label.length() > 63) {
                throw new IOException("Invalid label length in name: " + label);
            }
            baos.write(label.length());
            baos.write(label.getBytes("UTF-8"));
        }
        baos.write(0x00);
        return baos.toByteArray();
    }

    // Build DNS query packet
    private static QueryResult buildQuery(String qname, String queryTypeStr) {
        // Generate a random transaction ID
        int transactionId = new Random().nextInt(65536); // 0 to 65535 since it's 16-bit
        //RD = 1 since we want recursion
        int flags = 0x0100;
        int qdcount = 1, ancount = 0, nscount = 0, arcount = 0;

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            // Building the header
            dos.writeShort(transactionId & 0xFFFF); // we want to ensure that it's lower 16-bits
            dos.writeShort(flags & 0xFFFF);
            dos.writeShort(qdcount);
            dos.writeShort(ancount);
            dos.writeShort(nscount);
            dos.writeShort(arcount);

            // Building the question
            dos.write(encodeName(qname));
            dos.writeShort(qtypeFromString(queryTypeStr) & 0xFFFF);
            dos.writeShort(CLASS_IN);

            byte[] packet = baos.toByteArray();
            return new QueryResult(transactionId, packet);
        } catch (IOException e) {
            System.err.println("ERROR\tFailed to build DNS query: " + e.getMessage());
            System.exit(1);
            return null;
        }
    }

    private static SendResult sendQuery(InetAddress serverAddr,
            int port,
            int timeoutSeconds,
            int maxRetries,
            String qname,
            String queryTypeStr) {
        int retries = 0;
        while (retries < maxRetries) {
            DatagramSocket sock = null;
            try {
                sock = new DatagramSocket();
                // Set socket timeout in milliseconds
                sock.setSoTimeout(Math.max(0, timeoutSeconds) * 1000);

                // Build query packet
                QueryResult q = buildQuery(qname, queryTypeStr);
                DatagramPacket sendPacket = new DatagramPacket(q.packet, q.packet.length, serverAddr, port);

                //start time in nanoseconds 
                long startNs = System.nanoTime();
                sock.send(sendPacket);

                //Buffer to store data received from the server
                byte[] buffer = new byte[1024];
                DatagramPacket receivedPacket = new DatagramPacket(buffer, buffer.length);
                sock.receive(receivedPacket);
                long elapsedMs = (System.nanoTime() - startNs) / 1_000_000;

                // Copy only the received data without unused space 
                byte[] resp = Arrays.copyOf(receivedPacket.getData(), receivedPacket.getLength());
                return new SendResult(q.transactionId, resp, elapsedMs, retries);

            } catch (SocketTimeoutException te) {
                System.out.println("Timeout occurred. Retrying " + (retries + 1) + "/" + maxRetries + "...");
                retries++;
            } catch (IOException ioe) {
                System.err.println("ERROR\tSocket error: " + ioe.getMessage());
                System.exit(1);
            } finally {
                if (sock != null) {
                    sock.close();
                }
            }
        }
        System.err.println("ERROR\tMaximum number of retries " + maxRetries + " exceeded");
        System.exit(1);
        return null; // unreachable
    }

    private void parseAnswer(byte[] response) {
        // Implementation of response parsing can be added here
    }

    private void parseName() {
        // Implementation of name parsing can be added here 
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

        int timeout = Integer.parseInt(params[0]);
        if (timeout < 0) {
            System.err.println("ERROR \t Timeout must be positive");
            System.exit(1);
        }

        int maxRetries = Integer.parseInt(params[1]);
        if (maxRetries < 0) {
            System.err.println("ERROR \t Retries must be positive");
            System.exit(1);
        }

        int port = Integer.parseInt(params[2]);
        if (port < 1 || port > 65535) {
            System.err.println("ERROR \t Port must be in range 1-65535");
            System.exit(1);
        }
        String queryType = params[3];
        String server = params[4];
        String name = params[5];

        // Print parsed info
        System.out.println("DnsClient sending request for " + name);
        System.out.println("Server: " + server);
        System.out.println("Request type: " + queryType);

        InetAddress serverAddress = convertToInetAddress(server);
        if (serverAddress == null) {
            System.err.println("ERROR \t Invalid server IP address");
            System.exit(1);
        }

        //Sending the query
        SendResult r = sendQuery(serverAddress, port, timeout, maxRetries, name, queryType);

        //Logging the result
        System.out.println("Transaction ID of query:" + r.transactionId);
        System.out.println("Received " + r.response.length + " bytes in " + r.elapsedMillis + " ms"
                + " (retries used: " + r.retriesUsed + ")");
        System.out.println("Response received after " + r.elapsedMillis + "ms (" + r.retriesUsed + " retries)");
    }
};
