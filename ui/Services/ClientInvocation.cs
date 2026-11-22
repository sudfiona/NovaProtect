using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NovaProtect.UI.Services;

internal sealed class ClientInvocation : IDisposable
{
    private readonly NamedPipeServerStream _pipe;

    private ClientInvocation(NamedPipeServerStream pipe) => _pipe = pipe;

    internal static ClientInvocation Create(ProcessStartInfo start)
    {
        ClientIntegrity.EnsureVerified();
        var name = "novaprotect-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly, 4096, 4096);
        start.Environment["NOVAPROTECT_INVOCATION_PIPE"] = name;
        return new ClientInvocation(pipe);
    }

    internal async Task AuthorizeAsync(Process child, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var stage = "等待保护核心连接";
        try
        {
            var connection = _pipe.WaitForConnectionAsync(deadline.Token);
            var exited = child.WaitForExitAsync(deadline.Token);
            if (await Task.WhenAny(connection, exited) == exited && !connection.IsCompletedSuccessfully)
                throw new InvalidDataException($"保护核心拒绝调用：0x{child.ExitCode:X8}。");
            await connection;
            stage = "验证保护核心进程";
            if (!GetNamedPipeClientProcessId(_pipe.SafePipeHandle.DangerousGetHandle(), out var pid) || pid != child.Id)
                throw new InvalidOperationException("Unexpected core process connected to the invocation pipe.");
            stage = "读取授权挑战";
            var challenge = new byte[40];
            await _pipe.ReadExactlyAsync(challenge, deadline.Token);
            if (!challenge.AsSpan(0, 8).SequenceEqual("NPGATE01"u8)) throw new InvalidDataException("Invocation protocol");
            stage = "返回授权挑战";
            await _pipe.WriteAsync(challenge, deadline.Token);
            await _pipe.FlushAsync(deadline.Token);
        }
        catch (EndOfStreamException exception)
        {
            var exit = child.HasExited ? $"退出码 0x{child.ExitCode:X8}" : "核心连接已关闭";
            try { if (!child.HasExited) child.Kill(true); } catch { /* cleanup best-effort */ }
            throw new InvalidDataException(
                $"保护核心在“{stage}”阶段提前断开（{exit}）。客户端组件可能不完整或签名已失效，请重新安装最新客户端。",
                exception);
        }
        catch (IOException exception)
        {
            var exit = child.HasExited ? $"退出码 0x{child.ExitCode:X8}" : "核心连接已关闭";
            try { if (!child.HasExited) child.Kill(true); } catch { /* cleanup best-effort */ }
            throw new InvalidDataException(
                $"保护核心在“{stage}”阶段连接中断（{exit}）。客户端组件可能不完整或签名已失效，请重新安装最新客户端。",
                exception);
        }
        catch
        {
            try { if (!child.HasExited) child.Kill(true); } catch { /* cleanup best-effort */ }
            throw;
        }
    }

    public void Dispose() => _pipe.Dispose();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(nint pipe, out uint pid);
}
