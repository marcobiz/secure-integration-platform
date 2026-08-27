using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace SecureIntegration.ConnectorPacks.Healthcare.FSE2.Integration.Tests;

internal static class Fse2T03FrozenDataset
{
    internal const string RepositoryUrl = "https://github.com/ministero-salute/it-fse-accreditamento";
    internal const string Commit = "d937255fd7e9c079c5641c537da17fe98a2f2259";
    internal const string XmlPath = "Test Case/Validazione/Documenti XML Casi OK/8 - Casi OK Profilo Sanitario Sintetico/PSS476.xml";
    internal const string XmlBlob = "6b654344431a21e02b979ab4907bc53b38cb4143";
    internal const int XmlBytes = 58_712;
    internal const string XmlSha256 = "7B54299D5AD7E87CA7D5569E98ADAC2D687D3E9432FD4D015194E733A2ADAABD";
    internal const string SelectedPdfPath = "GATEWAY/A1#111#DAVINCI.CARE/DaVinci Healthcare/DaVinci/3.3/FILES/PSS476.pdf";
    internal const string SelectedPdfBlob = "a4bf835cbf08661a6c530f95bdea1770e0ca4ad0";
    internal const int SelectedPdfBytes = 60_148;
    internal const string SelectedPdfSha256 = "129BE437228376B897B8D176DE099CA165714901DA3CB7B78EE2F9B68F4A252E";

    internal static async Task<Snapshot> ReadAsync(string repositoryPath, CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(repositoryPath);
        if (!Directory.Exists(fullPath)) throw new InvalidOperationException("FSE2_T03_DATASET_PATH_MISSING");

        GitResult head = await GitAsync(fullPath, cancellationToken, "rev-parse", "HEAD");
        RequireSuccess(head, "FSE2_T03_DATASET_HEAD_UNREADABLE");
        if (!string.Equals(head.Text.Trim(), Commit, StringComparison.Ordinal))
            throw new InvalidOperationException("FSE2_T03_DATASET_HEAD_MISMATCH");

        GitResult symbolicHead = await GitAsync(fullPath, cancellationToken, "symbolic-ref", "-q", "HEAD");
        if (symbolicHead.ExitCode == 0) throw new InvalidOperationException("FSE2_T03_DATASET_HEAD_NOT_DETACHED");
        if (symbolicHead.ExitCode != 1) throw new InvalidOperationException("FSE2_T03_DATASET_HEAD_UNREADABLE");

        GitResult topLevel = await GitAsync(fullPath, cancellationToken, "rev-parse", "--show-toplevel");
        RequireSuccess(topLevel, "FSE2_T03_DATASET_REPOSITORY_UNREADABLE");
        if (!Path.GetFullPath(topLevel.Text.Trim()).Equals(fullPath, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("FSE2_T03_DATASET_REPOSITORY_PATH_MISMATCH");

        GitResult remote = await GitAsync(fullPath, cancellationToken, "config", "--get", "remote.origin.url");
        RequireSuccess(remote, "FSE2_T03_DATASET_REMOTE_UNREADABLE");
        if (!NormalizeRepositoryUrl(remote.Text).Equals(NormalizeRepositoryUrl(RepositoryUrl), StringComparison.Ordinal))
            throw new InvalidOperationException("FSE2_T03_DATASET_REMOTE_MISMATCH");

        GitResult partialClone = await GitAsync(fullPath, cancellationToken, "config", "--get", "extensions.partialClone");
        if (partialClone.ExitCode != 1)
            throw new InvalidOperationException("FSE2_T03_DATASET_PARTIAL_CLONE_FORBIDDEN");
        GitResult promisor = await GitAsync(fullPath, cancellationToken, "config", "--get-regexp", "^remote\\..*\\.promisor$");
        if (promisor.ExitCode != 1)
            throw new InvalidOperationException("FSE2_T03_DATASET_PROMISOR_FORBIDDEN");

        GitResult treeResult = await GitAsync(fullPath, cancellationToken, "ls-tree", "-r", "-z", Commit);
        RequireSuccess(treeResult, "FSE2_T03_DATASET_TREE_UNREADABLE");
        Dictionary<string, string> tree = ParseTree(treeResult.Output);
        if (!tree.TryGetValue(XmlPath, out string? xmlBlob) || !xmlBlob.Equals(XmlBlob, StringComparison.Ordinal))
            throw new InvalidOperationException("FSE2_T03_XML_BLOB_MISMATCH");

        await using GitBatchReader objects = await GitBatchReader.StartAsync(fullPath, cancellationToken);
        byte[] xml = await objects.ReadBlobAsync($"{Commit}:{XmlPath}", cancellationToken);
        AssertIdentity(xml, XmlBytes, XmlSha256, "FSE2_T03_XML_IDENTITY_MISMATCH");

        List<ExecutedRecord> executed = [];
        int rawId476Rows = 0;
        string[] xlsxPaths = tree.Keys
            .Where(path => path.EndsWith(".xlsx", StringComparison.OrdinalIgnoreCase) &&
                !Path.GetFileName(path).StartsWith("~$", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();
        foreach (string xlsxPath in xlsxPaths)
        {
            byte[] workbook = await objects.ReadBlobAsync($"{Commit}:{xlsxPath}", cancellationToken);
            foreach (WorkbookRow row in ReadWorkbookRows(workbook))
            {
                if (!IsCase476(row.Values)) continue;
                rawId476Rows++;
                if (Cell(row.Values, 9).Equals("SI", StringComparison.OrdinalIgnoreCase))
                    executed.Add(new(xlsxPath, row.Sheet, row.Number, row.Values));
            }
        }

        List<PdfCandidate> candidates = [];
        foreach (ExecutedRecord record in executed)
        {
            string root = record.WorkbookPath[..record.WorkbookPath.LastIndexOf('/')];
            string filesPrefix = root + "/FILES/";
            string[] directPdfs = tree.Keys
                .Where(path => path.StartsWith(filesPrefix, StringComparison.Ordinal) &&
                    path.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase) &&
                    !path[filesPrefix.Length..].Contains('/', StringComparison.Ordinal))
                .Order(StringComparer.Ordinal)
                .ToArray();
            string? selected = SelectCandidate(record, directPdfs);
            if (selected is null)
            {
                if (directPdfs.Length != 0) throw new InvalidOperationException("FSE2_T03_PDF_CANDIDATE_NOT_UNIQUE");
                continue;
            }

            byte[] pdf = await objects.ReadBlobAsync($"{Commit}:{selected}", cancellationToken);
            bool parseable = TryReadEmbeddedCda(pdf, out byte[] embeddedCda);
            string? embeddedSha = parseable ? Sha256(embeddedCda) : null;
            candidates.Add(new(
                selected,
                tree[selected],
                pdf.Length,
                Sha256(pdf),
                parseable,
                parseable && embeddedCda.Length == xml.Length &&
                    CryptographicOperations.FixedTimeEquals(embeddedCda, xml),
                embeddedSha));
        }

        PdfCandidate selectedPdf = candidates.Single(candidate => candidate.Path.Equals(SelectedPdfPath, StringComparison.Ordinal));
        if (!selectedPdf.Blob.Equals(SelectedPdfBlob, StringComparison.Ordinal))
            throw new InvalidOperationException("FSE2_T03_SELECTED_PDF_BLOB_MISMATCH");
        byte[] selectedPdfContent = await objects.ReadBlobAsync($"{Commit}:{SelectedPdfPath}", cancellationToken);
        AssertIdentity(selectedPdfContent, SelectedPdfBytes, SelectedPdfSha256, "FSE2_T03_SELECTED_PDF_IDENTITY_MISMATCH");

        return new(fullPath, rawId476Rows, executed, candidates, selectedPdfContent);
    }

    private static string? SelectCandidate(ExecutedRecord record, string[] directPdfs)
    {
        if (directPdfs.Length == 0) return null;
        string joined = string.Join(';', record.Values);
        Match explicitFile = Regex.Match(
            joined,
            @"(?:^|[;\s])file=(?<name>[^;]+?\.pdf)(?:;|$)",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
        if (explicitFile.Success)
        {
            string name = explicitFile.Groups["name"].Value.Trim();
            return AssertSingle(directPdfs.Where(path => Path.GetFileName(path).Equals(name, StringComparison.OrdinalIgnoreCase)));
        }

        string? byIdentifier = AssertAtMostSingle(directPdfs.Where(path => Regex.IsMatch(
            Path.GetFileNameWithoutExtension(path),
            @"(?<!\d)476(?!\d)",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1))));
        if (byIdentifier is not null) return byIdentifier;

        if (DateTimeOffset.TryParse(Cell(record.Values, 6), CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out DateTimeOffset execution))
        {
            var timed = directPdfs.Select(path => new { Path = path, Delta = TimeDelta(Path.GetFileNameWithoutExtension(path), execution) })
                .Where(value => value.Delta.HasValue)
                .OrderBy(value => value.Delta)
                .ToArray();
            if (timed.Length > 0 && timed[0].Delta <= TimeSpan.FromMinutes(5) &&
                (timed.Length == 1 || timed[0].Delta < timed[1].Delta))
                return timed[0].Path;
        }

        Match caseNumber = Regex.Match(
            Cell(record.Values, 3),
            @"_CT(?<number>\d+)$",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
        if (caseNumber.Success)
        {
            string number = Regex.Escape(caseNumber.Groups["number"].Value);
            string pattern = $@"(?:CT|CASO\s+DI\s+TEST\s*|_)(?:{number})(?:\D|$)|(?:^|[_-])T{number}(?:[_-])";
            string? byCase = AssertAtMostSingle(directPdfs.Where(path => Regex.IsMatch(
                Path.GetFileNameWithoutExtension(path),
                pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(1))));
            if (byCase is not null) return byCase;
        }

        return directPdfs.Length == 1 ? directPdfs[0] : null;
    }

    private static TimeSpan? TimeDelta(string fileName, DateTimeOffset execution)
    {
        MatchCollection matches = Regex.Matches(
            fileName,
            @"(?<!\d)(?<hour>[0-2]\d)\.(?<minute>[0-5]\d)\.(?<second>[0-5]\d)(?!\d)",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(1));
        if (matches.Count != 1) return null;
        Match match = matches[0];
        int fileSeconds = int.Parse(match.Groups["hour"].Value, CultureInfo.InvariantCulture) * 3600 +
            int.Parse(match.Groups["minute"].Value, CultureInfo.InvariantCulture) * 60 +
            int.Parse(match.Groups["second"].Value, CultureInfo.InvariantCulture);
        int executionSeconds = execution.Hour * 3600 + execution.Minute * 60 + execution.Second;
        int delta = Math.Abs(fileSeconds - executionSeconds);
        return TimeSpan.FromSeconds(Math.Min(delta, 86_400 - delta));
    }

    private static string AssertSingle(IEnumerable<string> values) => values.Single();

    private static string? AssertAtMostSingle(IEnumerable<string> values)
    {
        string[] materialized = values.Take(2).ToArray();
        if (materialized.Length > 1) throw new InvalidOperationException("FSE2_T03_PDF_CANDIDATE_AMBIGUOUS");
        return materialized.SingleOrDefault();
    }

    private static bool TryReadEmbeddedCda(byte[] pdf, out byte[] embeddedCda)
    {
        embeddedCda = [];
        try
        {
            string text = Encoding.Latin1.GetString(pdf);
            List<string> cdaFileSpecs = [];
            foreach (string token in new[] { "/Type /Filespec", "/Type/Filespec" })
            {
                int search = 0;
                while ((search = text.IndexOf(token, search, StringComparison.Ordinal)) >= 0)
                {
                    int objectMarker = text.LastIndexOf(" obj", search, StringComparison.Ordinal);
                    int dictionaryStart = objectMarker >= 0
                        ? text.IndexOf("<<", objectMarker, StringComparison.Ordinal)
                        : -1;
                    int objectEnd = text.IndexOf("endobj", search, StringComparison.Ordinal);
                    if (dictionaryStart >= 0 && objectEnd > search)
                    {
                        string candidate = text[dictionaryStart..objectEnd];
                        if (candidate.Contains("cda.xml", StringComparison.OrdinalIgnoreCase) ||
                            candidate.Contains("6364612E786D6C", StringComparison.OrdinalIgnoreCase))
                            cdaFileSpecs.Add(candidate);
                    }
                    search += token.Length;
                }
            }
            if (cdaFileSpecs.Count != 1) return false;
            string fileSpec = cdaFileSpecs[0];
            Match embeddedReference = Regex.Match(
                fileSpec,
                @"/EF\s*<<(?:(?!>>).)*?/F\s+(?<object>\d+)\s+(?<generation>\d+)\s+R",
                RegexOptions.Singleline | RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(1));
            if (!embeddedReference.Success)
            {
                Match efDictionaryReference = Regex.Match(
                    fileSpec,
                    @"/EF\s+(?<object>\d+)\s+(?<generation>\d+)\s+R",
                    RegexOptions.CultureInvariant,
                    TimeSpan.FromSeconds(1));
                if (!efDictionaryReference.Success) return false;
                string efDictionary = ReadPdfObject(
                    text,
                    efDictionaryReference.Groups["object"].Value,
                    efDictionaryReference.Groups["generation"].Value);
                embeddedReference = Regex.Match(
                    efDictionary,
                    @"/F\s+(?<object>\d+)\s+(?<generation>\d+)\s+R",
                    RegexOptions.CultureInvariant,
                    TimeSpan.FromSeconds(1));
                if (!embeddedReference.Success) return false;
            }

            string embeddedObject = ReadPdfObject(
                text,
                embeddedReference.Groups["object"].Value,
                embeddedReference.Groups["generation"].Value);
            int streamMarker = embeddedObject.IndexOf("stream", StringComparison.Ordinal);
            if (streamMarker < 0) return false;
            string dictionary = embeddedObject[..streamMarker];
            if (dictionary.Contains("<<<<<<<", StringComparison.Ordinal) || dictionary.Contains("=======", StringComparison.Ordinal) ||
                dictionary.Contains(">>>>>>>", StringComparison.Ordinal)) return false;
            int objectOffset = text.IndexOf(embeddedObject, StringComparison.Ordinal);
            if (objectOffset < 0) return false;
            int streamStart = objectOffset + streamMarker + "stream".Length;
            if (streamStart < pdf.Length && pdf[streamStart] == (byte)'\r') streamStart++;
            if (streamStart < pdf.Length && pdf[streamStart] == (byte)'\n') streamStart++;
            int streamEnd = text.IndexOf("endstream", streamStart, StringComparison.Ordinal);
            if (streamEnd < streamStart) return false;
            while (streamEnd > streamStart && (pdf[streamEnd - 1] == (byte)'\r' || pdf[streamEnd - 1] == (byte)'\n')) streamEnd--;
            int available = streamEnd - streamStart;
            Match lengthMatch = Regex.Match(
                dictionary,
                @"/Length\s+(?<length>\d+)(?!\s+\d+\s+R)",
                RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(1));
            int encodedLength = lengthMatch.Success && int.TryParse(lengthMatch.Groups["length"].Value, CultureInfo.InvariantCulture, out int declared) &&
                declared <= available ? declared : available;
            byte[] encoded = pdf.AsSpan(streamStart, encodedLength).ToArray();
            if (dictionary.Contains("/FlateDecode", StringComparison.Ordinal))
            {
                using MemoryStream source = new(encoded, writable: false);
                using ZLibStream inflater = new(source, CompressionMode.Decompress);
                using MemoryStream decoded = new();
                inflater.CopyTo(decoded);
                embeddedCda = decoded.ToArray();
            }
            else
            {
                embeddedCda = encoded;
            }
            return embeddedCda.Length > 0;
        }
        catch (Exception exception) when (exception is InvalidDataException or IOException or ArgumentException)
        {
            embeddedCda = [];
            return false;
        }
    }

    private static string ReadPdfObject(string pdf, string objectNumber, string generation)
    {
        string marker = objectNumber + " " + generation + " obj";
        int search = 0;
        while ((search = pdf.IndexOf(marker, search, StringComparison.Ordinal)) >= 0)
        {
            bool lineStart = search == 0 || pdf[search - 1] is '\r' or '\n';
            int bodyStart = search + marker.Length;
            if (lineStart)
            {
                int objectEnd = pdf.IndexOf("endobj", bodyStart, StringComparison.Ordinal);
                if (objectEnd > bodyStart) return pdf[bodyStart..objectEnd];
            }
            search = bodyStart;
        }
        return string.Empty;
    }

    private static IEnumerable<WorkbookRow> ReadWorkbookRows(byte[] workbook)
    {
        using MemoryStream memory = new(workbook, writable: false);
        using ZipArchive archive = new(memory, ZipArchiveMode.Read);
        XNamespace spreadsheet = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
        string[] sharedStrings = ReadSharedStrings(archive, spreadsheet);
        foreach (ZipArchiveEntry sheet in archive.Entries
            .Where(entry => Regex.IsMatch(entry.FullName, @"^xl/worksheets/sheet\d+\.xml$", RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)))
            .OrderBy(entry => entry.FullName, StringComparer.Ordinal))
        {
            using Stream stream = sheet.Open();
            XDocument document = XDocument.Load(stream, LoadOptions.None);
            foreach (XElement row in document.Descendants(spreadsheet + "row"))
            {
                Dictionary<int, string> cells = [];
                foreach (XElement cell in row.Elements(spreadsheet + "c"))
                {
                    string? reference = (string?)cell.Attribute("r");
                    if (string.IsNullOrEmpty(reference)) continue;
                    int column = ColumnIndex(reference);
                    string type = (string?)cell.Attribute("t") ?? string.Empty;
                    string value;
                    if (type.Equals("inlineStr", StringComparison.Ordinal))
                        value = string.Concat(cell.Descendants(spreadsheet + "t").Select(node => node.Value));
                    else
                    {
                        string raw = cell.Element(spreadsheet + "v")?.Value ?? string.Empty;
                        value = type.Equals("s", StringComparison.Ordinal) && int.TryParse(raw, CultureInfo.InvariantCulture, out int index)
                            ? sharedStrings[index]
                            : raw;
                    }
                    cells[column] = value.Trim();
                }
                if (cells.Count == 0) continue;
                string[] values = new string[cells.Keys.Max() + 1];
                foreach ((int index, string value) in cells) values[index] = value;
                yield return new(sheet.FullName, (int?)row.Attribute("r") ?? 0, values);
            }
        }
    }

    private static string[] ReadSharedStrings(ZipArchive archive, XNamespace spreadsheet)
    {
        ZipArchiveEntry? entry = archive.GetEntry("xl/sharedStrings.xml");
        if (entry is null) return [];
        using Stream stream = entry.Open();
        XDocument document = XDocument.Load(stream, LoadOptions.None);
        return document.Descendants(spreadsheet + "si")
            .Select(item => string.Concat(item.Descendants(spreadsheet + "t").Select(node => node.Value)))
            .ToArray();
    }

    private static int ColumnIndex(string reference)
    {
        int value = 0;
        foreach (char character in reference)
        {
            if (character is < 'A' or > 'Z') break;
            value = checked(value * 26 + character - 'A' + 1);
        }
        return value - 1;
    }

    private static bool IsCase476(IReadOnlyList<string> values)
    {
        string value = Cell(values, 0);
        return value.Equals("476", StringComparison.Ordinal) || value.Equals("476.0", StringComparison.Ordinal);
    }

    private static string Cell(IReadOnlyList<string> values, int index) => index < values.Count ? values[index] ?? string.Empty : string.Empty;

    private static Dictionary<string, string> ParseTree(byte[] bytes)
    {
        Dictionary<string, string> tree = new(StringComparer.Ordinal);
        foreach (ReadOnlyMemory<byte> entry in Split(bytes, 0))
        {
            int tab = entry.Span.IndexOf((byte)'\t');
            if (tab < 0) throw new InvalidOperationException("FSE2_T03_DATASET_TREE_INVALID");
            string metadata = Encoding.ASCII.GetString(entry.Span[..tab]);
            string[] fields = metadata.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 3 || !fields[1].Equals("blob", StringComparison.Ordinal)) continue;
            tree.Add(Encoding.UTF8.GetString(entry.Span[(tab + 1)..]), fields[2]);
        }
        return tree;
    }

    private static IEnumerable<ReadOnlyMemory<byte>> Split(byte[] bytes, byte delimiter)
    {
        int start = 0;
        for (int index = 0; index < bytes.Length; index++)
        {
            if (bytes[index] != delimiter) continue;
            if (index > start) yield return bytes.AsMemory(start, index - start);
            start = index + 1;
        }
        if (start != bytes.Length) throw new InvalidOperationException("FSE2_T03_DATASET_TREE_NOT_NUL_TERMINATED");
    }

    private static void AssertIdentity(byte[] content, int expectedBytes, string expectedSha256, string error)
    {
        if (content.Length != expectedBytes || !Sha256(content).Equals(expectedSha256, StringComparison.Ordinal))
            throw new InvalidOperationException(error);
    }

    private static string Sha256(byte[] value) => Convert.ToHexString(SHA256.HashData(value));

    private static string NormalizeRepositoryUrl(string value) => value.Trim().TrimEnd('/').RemoveSuffix(".git");

    private static void RequireSuccess(GitResult result, string error)
    {
        if (result.ExitCode != 0) throw new InvalidOperationException(error);
    }

    private static async Task<GitResult> GitAsync(string repositoryPath, CancellationToken cancellationToken, params string[] arguments)
    {
        ProcessStartInfo start = GitStart(repositoryPath);
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        using Process process = Process.Start(start) ?? throw new InvalidOperationException("FSE2_T03_GIT_START_FAILED");
        Task<byte[]> output = ReadAllAsync(process.StandardOutput.BaseStream, cancellationToken);
        Task<string> error = process.StandardError.ReadToEndAsync(cancellationToken);
        await process.WaitForExitAsync(cancellationToken);
        return new(process.ExitCode, await output, await error);
    }

    private static ProcessStartInfo GitStart(string repositoryPath)
    {
        ProcessStartInfo start = new("git")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        start.ArgumentList.Add("-C");
        start.ArgumentList.Add(repositoryPath);
        start.Environment["GIT_TERMINAL_PROMPT"] = "0";
        start.Environment["GIT_NO_LAZY_FETCH"] = "1";
        start.Environment["GIT_ALLOW_PROTOCOL"] = "file";
        return start;
    }

    private static async Task<byte[]> ReadAllAsync(Stream stream, CancellationToken cancellationToken)
    {
        using MemoryStream buffer = new();
        await stream.CopyToAsync(buffer, cancellationToken);
        return buffer.ToArray();
    }

    internal sealed record Snapshot(
        string RepositoryPath,
        int RawId476Rows,
        IReadOnlyList<ExecutedRecord> ExecutedRecords,
        IReadOnlyList<PdfCandidate> Candidates,
        byte[] SelectedPdfContent);

    internal sealed record ExecutedRecord(string WorkbookPath, string Sheet, int Row, IReadOnlyList<string> Values)
    {
        internal string TestCode => Cell(Values, 3);
    }

    internal sealed record PdfCandidate(
        string Path,
        string Blob,
        int Bytes,
        string Sha256,
        bool Parseable,
        bool EmbeddedCdaMatch,
        string? EmbeddedCdaSha256);

    private sealed record WorkbookRow(string Sheet, int Number, IReadOnlyList<string> Values);

    private sealed record GitResult(int ExitCode, byte[] Output, string Error)
    {
        internal string Text => Encoding.UTF8.GetString(Output);
    }

    private sealed class GitBatchReader : IAsyncDisposable
    {
        private readonly Process process;

        private GitBatchReader(Process process) => this.process = process;

        internal static Task<GitBatchReader> StartAsync(string repositoryPath, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ProcessStartInfo start = GitStart(repositoryPath);
            start.ArgumentList.Add("cat-file");
            start.ArgumentList.Add("--batch");
            Process process = Process.Start(start) ?? throw new InvalidOperationException("FSE2_T03_GIT_BATCH_START_FAILED");
            return Task.FromResult(new GitBatchReader(process));
        }

        internal async Task<byte[]> ReadBlobAsync(string objectName, CancellationToken cancellationToken)
        {
            await process.StandardInput.WriteLineAsync(objectName.AsMemory(), cancellationToken);
            await process.StandardInput.FlushAsync(cancellationToken);
            string header = await ReadAsciiLineAsync(process.StandardOutput.BaseStream, cancellationToken);
            string[] fields = header.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length != 3 || !fields[1].Equals("blob", StringComparison.Ordinal) ||
                !int.TryParse(fields[2], NumberStyles.None, CultureInfo.InvariantCulture, out int length))
                throw new InvalidOperationException("FSE2_T03_GIT_OBJECT_MISSING");
            byte[] content = new byte[length];
            await process.StandardOutput.BaseStream.ReadExactlyAsync(content, cancellationToken);
            int delimiter = process.StandardOutput.BaseStream.ReadByte();
            if (delimiter != '\n') throw new InvalidOperationException("FSE2_T03_GIT_BATCH_PROTOCOL_INVALID");
            return content;
        }

        private static async Task<string> ReadAsciiLineAsync(Stream stream, CancellationToken cancellationToken)
        {
            using MemoryStream line = new();
            byte[] single = new byte[1];
            while (true)
            {
                int read = await stream.ReadAsync(single, cancellationToken);
                if (read == 0) throw new EndOfStreamException("FSE2_T03_GIT_BATCH_ENDED");
                if (single[0] == '\n') return Encoding.ASCII.GetString(line.ToArray());
                line.WriteByte(single[0]);
            }
        }

        public async ValueTask DisposeAsync()
        {
            process.StandardInput.Close();
            await process.WaitForExitAsync();
            string error = await process.StandardError.ReadToEndAsync();
            int exitCode = process.ExitCode;
            process.Dispose();
            if (exitCode != 0) throw new InvalidOperationException("FSE2_T03_GIT_BATCH_FAILED:" + error.Trim());
        }
    }

    private static string RemoveSuffix(this string value, string suffix) =>
        value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase) ? value[..^suffix.Length] : value;
}
