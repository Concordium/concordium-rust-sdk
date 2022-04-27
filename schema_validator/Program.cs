using Newtonsoft.Json.Schema;
using Newtonsoft.Json.Linq;

if (args.Length != 2)
{
    Console.WriteLine("Expected arguments: SCHEMA_FILE JSON_FILE");
    return -1;
}

string schema_contents = System.IO.File.ReadAllText(args[0]);
JSchema schema = JSchema.Parse(schema_contents);

string json_file = args[1];
string json_contents = System.IO.File.ReadAllText(json_file);
JObject json = JObject.Parse(json_contents);

if (json.IsValid(schema))
{
    Console.WriteLine($"{json_file}");
    return 0;
}
else
{
    Console.WriteLine($"{json_file} --- FAIL ---");
    return -1;
}
