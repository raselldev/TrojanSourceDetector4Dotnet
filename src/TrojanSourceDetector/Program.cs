using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

using TrojanSourceDetector;



var originalColor = Console.ForegroundColor;
var defaultColor = ConsoleColor.White;
Console.ForegroundColor = ConsoleColor.DarkCyan;


var nonRenderingCategories = new UnicodeCategory[] {
UnicodeCategory.Control,
UnicodeCategory.OtherNotAssigned,
UnicodeCategory.Format,
UnicodeCategory.Surrogate };


void alert(string text, int line)
{
    var defaultForegroundColor = ConsoleColor.White;
    var defaultBackgroundColor = Console.BackgroundColor;
    Console.ForegroundColor = ConsoleColor.DarkRed;
    Console.Write("[Warning]: ");
    Console.ForegroundColor = defaultForegroundColor;
    Console.Write($"Terdapat Hidden characters pada posisi line {line}: ");
    Console.ForegroundColor = ConsoleColor.DarkRed;
    Console.Write(text);
    Console.ForegroundColor = defaultForegroundColor;
    Console.WriteLine();

    var start = Math.Max(0, line);
    var sourceLines = File.ReadAllLines(text).Skip(start).Take(1).ToArray();

    for (int i = 0; i < sourceLines.Length; ++i)
    {
        var sourceLine = sourceLines[i];
        Console.WriteLine($"Yang terlihat: [{start + i}] {sourceLine}");

        Console.Write($"Aktual    : [{start + i}] ");
        foreach (var c in sourceLine)
        {
            var (isPrintable, slug) = CharConverter(c);

            if (!isPrintable)
            {
                Console.BackgroundColor = ConsoleColor.DarkRed;
            }

            Console.Write(slug);

            if (!isPrintable)
            {
                Console.BackgroundColor = defaultBackgroundColor;
            }
        }

        Console.WriteLine();
    }

    Console.WriteLine();

    static (bool isPrintable, string slug) CharConverter(char c)
    {
        var nonRenderingCategories = new UnicodeCategory[] {
        UnicodeCategory.Control,
        UnicodeCategory.OtherNotAssigned,
        UnicodeCategory.Format,
        UnicodeCategory.Surrogate };

        var category = Char.GetUnicodeCategory(c);

        var isPrintable = Char.IsWhiteSpace(c) ||
                !nonRenderingCategories.Contains(category);

        if (isPrintable) return (true, $"{c}");

        return (false, $"\\u{(ushort)c:X}");
    }

}

string? GetPathFromUser()
{
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("Please enter a directory with one or more .NET projects to start (Full dir path): ");
    Console.ForegroundColor = defaultColor;

    return Console.ReadLine();
}

string? path = null;

while (path is null or "")
{
    if (args.Length == 0 || !Directory.Exists(args[0]))
    {
        path = GetPathFromUser();

        if (path == string.Empty)
        {
            Environment.Exit(0);
            return;
        }
    }
    else
    {
        path = args[0];
    }
}

Console.WriteLine();

List<EmojiRecord> whiteList = new();

Console.WriteLine("Emoji Whitelist.");
var jsonPath = Path.Combine(Path.GetDirectoryName(typeof(Program).Assembly.Location), "emojis.json");

whiteList = JsonSerializer.Deserialize<List<EmojiRecord>>(File.ReadAllText(jsonPath));
Console.WriteLine($"Terdapat {whiteList.Count} pada Emoji Whitelist.");


if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
{
    Console.ForegroundColor = ConsoleColor.DarkRed;
    Console.WriteLine("Invalid path");
    Console.ForegroundColor = defaultColor;
    return;
}

string[] dotnetFiles = Directory.GetFiles(path: path, "*.*", SearchOption.AllDirectories);

// Filter to common C# Project Files
var regex = new Regex(@".*\.(cs|cshtml|aspx|config|razor|xaml|csproj|resx|ettings\.[^\.]+\.json)$");

var issuesCount = 0;

var scannedFiles = 0;
var problemFiles = 0;

var problematicFilesList = new List<(string filename, List<int> lines)>();
var dotnetFilesCount = dotnetFiles.Count();
Console.WriteLine();
foreach (var dotnetFile in dotnetFiles)
{
    if (regex.IsMatch(dotnetFile))
    {
        string? currentLine = null;

        var sourceLines = File.ReadAllLines(dotnetFile);
        var lines = new List<int>();
        int lastReportedLine = -1;
        scannedFiles++;
        int positionInLine = -1;

        using StreamReader sr = new StreamReader(dotnetFile);
        int count = 0, line = 0;
        while (sr.Peek() >= 0)
        {
            var c = (char)sr.Read();
            count++; positionInLine++;
            if (currentLine is null)
            {
                currentLine = sourceLines[line];
            }
            if (c == '\n')
            {
                line++;
                positionInLine = -1;
                if (line < sourceLines.Length)
                {
                    currentLine = sourceLines[line];
                }
                continue;
            }
            var category = Char.GetUnicodeCategory(c);

            var isPrintable = Char.IsWhiteSpace(c) ||
                  !nonRenderingCategories.Contains(category);

            // Filter out Byte-Order-Marks and ESC sequences.
            if ((ushort)c == 0xFEFF)
            {
                continue;
            }

            if ((ushort)c == 0x7f)
            {
                continue;
            }

            if (!isPrintable)
            {

                var isSurrogate = Char.GetUnicodeCategory(c) == UnicodeCategory.Surrogate;
                var nextIsSurrogate = Char.GetUnicodeCategory(currentLine[positionInLine + 1]) == UnicodeCategory.Surrogate;
                var isSafe = false || (isSurrogate && nextIsSurrogate);
                if (isSurrogate)
                {
                    foreach (var emoji in whiteList)
                    {
                        var regexMatcher = new Regex(emoji.RegexPattern);

                        var matches = regexMatcher.Matches(currentLine).Cast<Match>().ToList();
                        var foundMatch = false;

                        foreach (var match in matches)
                        {
                            if (match.Index < positionInLine && match.Index + match.Length > positionInLine)
                            {
                                foundMatch = true;
                                break;
                            }
                        }

                        isSafe = foundMatch;

                        if (foundMatch)
                        {
                            break;
                        }
                    }
                }

                if (!isSafe && !nextIsSurrogate)
                {
                    issuesCount++;

                    if (lastReportedLine == -1)
                    {
                        problemFiles++;
                    }

                    if (lastReportedLine != line)
                    {
                        lines.Add(line);
                        lastReportedLine = line;
                        alert(dotnetFile, line);
                    }
                }
            }
        }

        sr.Close();

        sr.Dispose();

        if (lines.Count > 0)
        {
            problematicFilesList.Add((dotnetFile, lines));
        }
    }
}


if (issuesCount == 0)
{
    Console.ForegroundColor = ConsoleColor.DarkGreen;
    Console.WriteLine();
    Console.WriteLine($"Perfect! No problems have been detected in the analysis of {scannedFiles} files.");
    Console.ForegroundColor = originalColor;
    return;
}

Console.ForegroundColor = ConsoleColor.DarkYellow;
Console.WriteLine();
Console.WriteLine($"{problemFiles} files terdapat {issuesCount} issue yang terdeteksi dari total {scannedFiles} files yang di scan");
Console.ForegroundColor = defaultColor;

foreach (var (name, list) in problematicFilesList.OrderBy(t => t.filename))
{
    var lines = $"{name}: [{string.Join(",", list)}]";
    Console.WriteLine(lines);
}

Console.ForegroundColor = originalColor;

