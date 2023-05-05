using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using System;
using System.Threading;

namespace EtwHash
{
    public static class Program
    {
        private static void ShowHelp()
        {
            Console.WriteLine("Usage: EtwHash.exe [etl_file]");
        }

        static void Main(string[] args)
        {
            Console.WriteLine(args[0]);

            //Byte arrays from https://github.com/X-C3LL/SharpNTLMRawUnHide/blob/7f32c034dde2d70d9426a403357c81df632367b5/SharpNTLMRawUnhide/Program.cs#L12
            byte[] ntlmsspSig = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00 };
            byte[] ntlmsspType1 = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00 };
            byte[] ntlmsspType2 = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x02, 0x00, 0x00, 0x00 };
            byte[] ntlmsspType3 = { 0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00, 0x03, 0x00, 0x00, 0x00 };
            var serverChallenge = new byte[8];

            using (var source = new ETWTraceEventSource(args[0]))
            {
                var parser = new DynamicTraceEventParser(source);
                parser.All += delegate(TraceEvent data)
                {
                    switch (data.EventName)
                    {
                        case "EventID(40000)":
                            var eventArray = Helpers.ObjectToByteArray(data.PayloadValue(2));
                            var offset = 0;

                            while (offset != -1)
                            {
                                if (offset != 0)
                                {
                                    offset += ntlmsspSig.Length;
                                }
                                offset = Helpers.Search(eventArray, ntlmsspSig, offset, eventArray.Length);
                                if (offset == -1)
                                {
                                    break;
                                }

                                var found = Helpers.Search(eventArray, ntlmsspType2, offset, offset + ntlmsspType2.Length);
                                var found2 = Helpers.Search(eventArray, ntlmsspType1, offset, offset + ntlmsspType1.Length);

                                if (found > -1 || found2 > -1)
                                {
                                    Array.Copy(eventArray, offset + 24, serverChallenge, 0, 8);
                                }
                                found = Helpers.Search(eventArray, ntlmsspType3, offset, offset + ntlmsspType3.Length);

                                if (found > -1)
                                {
                                    var finalArray = new byte[eventArray.Length - offset];
                                    Array.Copy(eventArray, offset, finalArray, 0, eventArray.Length - offset);
                                    Console.WriteLine(Helpers.DecodeNTLM(finalArray, serverChallenge));
                                }
                            }
                            break;
                    }
                };
                source.Process();

            }
        }
    }
}
