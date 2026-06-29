using TokenBindingShowcase;
using TokenBindingShowcase.Demos;

// Entry point. Pick a path from the menu, or pass it as an argument:
//   dotnet run -- 1   (MSAL)   |   2 (Identity Web)   |   3 (AKV SDK)   |   4 (all)

AppSettings settings = AppSettings.Load();
Ux.Banner(settings);

string? choice = args.Length > 0 ? args[0].Trim() : null;
if (string.IsNullOrEmpty(choice))
{
    Ux.Menu();
    choice = Console.ReadLine()?.Trim();
}

switch (choice)
{
    case "1":
        await MsalDemo.RunAsync(settings);
        break;
    case "2":
        await IdWebDemo.RunAsync(settings);
        break;
    case "3":
        await AkvSdkDemo.RunAsync(settings);
        break;
    case "4":
        await MsalDemo.RunAsync(settings);
        await IdWebDemo.RunAsync(settings);
        await AkvSdkDemo.RunAsync(settings);
        break;
    default:
        Ux.Warn($"Nothing to run for '{choice}'. Re-run and choose 1-4.");
        break;
}

Console.WriteLine();
Ux.Info("Done. (On a non-KeyGuard dev box, acquisition will fail with a managed-identity error - that is expected.)");
