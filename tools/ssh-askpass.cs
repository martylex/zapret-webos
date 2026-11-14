using System;
public static class SshAskpass {
    public static int Main() {
        var password = Environment.GetEnvironmentVariable("FLOWSEAL_SSH_PASSWORD");
        if (password == null) return 1;
        Console.WriteLine(password);
        return 0;
    }
}
