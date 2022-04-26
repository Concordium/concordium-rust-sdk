using Newtonsoft.Json.Schema;
using Newtonsoft.Json.Linq;

if (args.Length != 2)
{
    Console.WriteLine("Expected arguments: SCHEMA_FILE JSON_FILE");
    return -1;
}

string schema_contents = System.IO.File.ReadAllText(args[0]);
JSchema schema = JSchema.Parse(schema_contents);

string json_contents = System.IO.File.ReadAllText(args[1]);
JObject json = JObject.Parse(json_contents);

if (json.IsValid(schema))
{
    return 0;
}
else
{
    return -1;
}
