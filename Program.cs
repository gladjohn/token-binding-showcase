using TokenBindingShowcase;
using TokenBindingShowcase.Demos;

// Entry point. With no argument you get an interactive menu that LOOPS until you exit.
// You can also run one path directly:  TokenBindingShowcase.exe 1|2|3|4|5

AppSettings settings = AppSettings.Load();
Ux.Banner(settings);

string? arg = args.Length > 0 ? args[0].Trim() : null;
if (!string.IsNullOrEmpty(arg))
{
    await Run(arg);          // one-shot (handy for scripting)
    return;
}

// Interactive: keep looping the menu so the window stays open between calls.
while (true)
{
    Ux.Menu();
    string? choice = Console.ReadLine()?.Trim();
    if (choice is "0" or "q" or "Q" or "exit")
    {
        Ux.Info("Goodbye.");
        break;
    }
    if (string.IsNullOrEmpty(choice))
        continue;

    await Run(choice);
    Console.WriteLine();
}

async Task Run(string choice)
{
    switch (choice)
    {
        case "1": await KeyGuardDemo.RunAsync(settings); break;
        case "2": await SoftwareKeyDemo.RunAsync(settings); break;
        case "3": await CertDemo.RunAsync(settings); break;
        case "4": await ClassicMsiDemo.RunAsync(settings); break;
        case "5": await MsalDemo.RunAsync(settings); break;
        case "6": await IdWebDemo.RunAsync(settings); break;
        case "7": await AkvSdkDemo.RunAsync(settings); break;
        case "8":
            await MsalDemo.RunAsync(settings);
            await IdWebDemo.RunAsync(settings);
            await AkvSdkDemo.RunAsync(settings);
            break;
        case "9": await ReplayDemo.RunAsync(settings); break;
        default:
            Ux.Warn($"Unknown option '{choice}'. Choose 0-9.");
            break;
    }
}

