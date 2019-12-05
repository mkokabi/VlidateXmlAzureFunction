using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Xml;
using System.Xml.Schema;
using Azure.Storage.Blobs;

namespace ValidateXml
{
    public static class ValidateFunction
    {
        [FunctionName("Validate")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            try
            {
                log.LogInformation("Validate function started.");

                string blobConnectionString = Environment.GetEnvironmentVariable("BLOB_CONNECT_STR");
                if (string.IsNullOrWhiteSpace(blobConnectionString))
                {
                    return new BadRequestObjectResult("Could not read the blob connection string. Please provide BLOB_CONNECT_STR environment variable.");
                }

                if (!req.Query.TryGetValue("xsd", out var xsdname))
                {
                    return new BadRequestObjectResult("Please provide the Scehma file name in the 'xsd' query parameter");
                }

                var blobServiceClient = new BlobServiceClient(blobConnectionString);
                var xsdContainerName = "xsd";

                var downloadInfo = await blobServiceClient.GetBlobContainerClient(xsdContainerName).GetBlobClient(xsdname).DownloadAsync();

                var xmlReaderSettings = new XmlReaderSettings();
                using (var xsdXmlReader = XmlReader.Create(downloadInfo.Value.Content))
                {
                    if (!req.Query.TryGetValue("ns", out var targetnamespace))
                    {
                        while (xsdXmlReader.Name != "xs:schema") { xsdXmlReader.Read(); } // skip the ?xml
                        targetnamespace = xsdXmlReader.GetAttribute("targetNamespace");
                    }

                    xmlReaderSettings.Schemas.Add(targetnamespace, xsdXmlReader);
                    xmlReaderSettings.ValidationType = ValidationType.Schema;
                    xmlReaderSettings.ValidationEventHandler += new ValidationEventHandler(ValidationEventHandler);
                    using (XmlReader xmlReader = XmlReader.Create(req.Body, xmlReaderSettings))
                    {
                        validationResult = "";
                        while (xmlReader.Read()) { }
                    }
                }

                return new OkObjectResult(string.IsNullOrWhiteSpace(validationResult) ? "OK" : validationResult);
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Something went wrong");
                return new BadRequestObjectResult("Exception " + ex.Message);
            }
        }

        static string validationResult;

        static void ValidationEventHandler(object sender, ValidationEventArgs e)
        {
            if (e.Severity == XmlSeverityType.Warning)
            {
                validationResult += "WARNING: ";
                validationResult += e.Message + Environment.NewLine;
            }
            else if (e.Severity == XmlSeverityType.Error)
            {
                validationResult += "ERROR: ";
                validationResult += e.Message + Environment.NewLine;
            }
        }
    }
}