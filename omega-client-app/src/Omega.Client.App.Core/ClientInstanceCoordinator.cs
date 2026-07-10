using System.Diagnostics;
using System.IO.Pipes;

namespace Omega.Client.App.Core;

public enum ClientInstanceCommand
{
    Activate,
    ExitForUpdate,
}

public sealed class ClientInstanceCoordinator : IDisposable
{
    private const string DefaultInstanceKey = "OmegaVpn.Client.App";
    private readonly string pipeName;
    private readonly Mutex mutex;
    private readonly bool ownsMutex;
    private readonly Action<ClientInstanceCommand> commandHandler;
    private readonly CancellationTokenSource cancellation = new();
    private readonly Task? listenerTask;
    private bool disposed;

    private ClientInstanceCoordinator(
        string instanceKey,
        int sessionId,
        Action<ClientInstanceCommand> commandHandler)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(instanceKey);
        this.commandHandler = commandHandler ?? throw new ArgumentNullException(nameof(commandHandler));

        var mutexName = OperatingSystem.IsWindows()
            ? $@"Local\{instanceKey}.{sessionId}"
            : $"{instanceKey}.{sessionId}";
        pipeName = $"{instanceKey}.{sessionId}";
        mutex = new Mutex(initiallyOwned: true, mutexName, out var createdNew);
        ownsMutex = createdNew;
        if (ownsMutex)
        {
            listenerTask = Task.Run(ListenAsync);
        }
    }

    public bool IsPrimary => ownsMutex;

    public static ClientInstanceCoordinator Create(Action<ClientInstanceCommand> commandHandler)
    {
        return Create(DefaultInstanceKey, CurrentSessionId(), commandHandler);
    }

    public static ClientInstanceCoordinator Create(
        string instanceKey,
        int sessionId,
        Action<ClientInstanceCommand> commandHandler)
    {
        return new ClientInstanceCoordinator(instanceKey, sessionId, commandHandler);
    }

    public bool SendToPrimary(ClientInstanceCommand command, TimeSpan timeout)
    {
        return TrySend(pipeName, command, timeout);
    }

    public static bool SendToPrimaryInstance(ClientInstanceCommand command, TimeSpan timeout)
    {
        var pipeName = $"{DefaultInstanceKey}.{CurrentSessionId()}";
        return TrySend(pipeName, command, timeout);
    }

    private async Task ListenAsync()
    {
        while (!cancellation.IsCancellationRequested)
        {
            try
            {
                using var pipe = new NamedPipeServerStream(
                    pipeName,
                    PipeDirection.In,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await pipe.WaitForConnectionAsync(cancellation.Token).ConfigureAwait(false);

                using var reader = new StreamReader(pipe);
                var line = await reader.ReadLineAsync(cancellation.Token).ConfigureAwait(false);
                if (Enum.TryParse<ClientInstanceCommand>(line, ignoreCase: true, out var command))
                {
                    commandHandler(command);
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                break;
            }
            catch (IOException) when (!cancellation.IsCancellationRequested)
            {
                // A client disconnected before sending a complete command. Keep listening.
            }
        }
    }

    private static bool TrySend(string pipeName, ClientInstanceCommand command, TimeSpan timeout)
    {
        if (timeout <= TimeSpan.Zero || timeout.TotalMilliseconds > int.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        try
        {
            using var pipe = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.Out,
                PipeOptions.CurrentUserOnly);
            pipe.Connect((int)timeout.TotalMilliseconds);
            using var writer = new StreamWriter(pipe) { AutoFlush = true };
            writer.WriteLine(command.ToString());
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (TimeoutException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    private static int CurrentSessionId()
    {
        return OperatingSystem.IsWindows() ? Process.GetCurrentProcess().SessionId : 0;
    }

    public void Dispose()
    {
        if (disposed)
        {
            return;
        }

        disposed = true;
        cancellation.Cancel();
        if (listenerTask is not null)
        {
            try
            {
                listenerTask.Wait(TimeSpan.FromSeconds(2));
            }
            catch (AggregateException ex) when (ex.InnerExceptions.All(inner => inner is OperationCanceledException))
            {
            }
        }

        cancellation.Dispose();
        if (ownsMutex)
        {
            mutex.ReleaseMutex();
        }
        mutex.Dispose();
    }
}
