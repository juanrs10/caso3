public class App {
    public static void main(String[] args) {
        // Scenario 1: Single iterative client making 32 requests
        System.out.println("Running Scenario 1: Single iterative client with 32 requests");
        runSingleClientScenario();

        // Scenario 2: Concurrent clients with varying numbers of delegates
        int[] delegateCounts = {4, 8, 32};  // Number of concurrent clients
        for (int count : delegateCounts) {
            System.out.println("Running Scenario 2 with " + count + " concurrent clients.");
            runConcurrentClientScenario(count);
        }
    }

    // Runs the first scenario: a single client sending multiple requests iteratively
    private static void runSingleClientScenario() {
        ServerMain server = new ServerMain();
        server.initializeMenu();  // Only initialize server keys if needed

        try {
            Thread.sleep(1000); // Ensure the server has started
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        ClientMain client = new ClientMain();
        for (int i = 0; i < 32; i++) {
            System.out.println("Sending request #" + (i + 1));
            client.sendRequest("cliente" + i, "paquete" + i);
        }
    }

    // Runs the second scenario with concurrent clients
    private static void runConcurrentClientScenario(int delegateCount) {
        ServerMain server = new ServerMain();
        server.initializeMenu();

        Thread serverThread = new Thread(() -> server.startServer());
        serverThread.start();

        // Ensure server has started
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Create and start client threads
        Thread[] clientThreads = new Thread[delegateCount];
        for (int i = 0; i < delegateCount; i++) {
            String userId = "cliente" + i;
            String packageId = "paquete" + i;
            clientThreads[i] = new Thread(() -> {
                ClientMain client = new ClientMain();
                client.sendRequest(userId, packageId);
            });
            clientThreads[i].start();
        }

        // Wait for all client threads to finish
        for (Thread clientThread : clientThreads) {
            try {
                clientThread.join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
