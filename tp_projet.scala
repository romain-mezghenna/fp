import org.apache.spark.sql.SparkSession
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types._

// Définir le schéma explicite pour CVE_Items uniquement
val cveSchema = ArrayType(StructType(Seq(
  StructField("cve", StructType(Seq(
    StructField("data_type", StringType, nullable = true),
    StructField("data_format", StringType, nullable = true),
    StructField("data_version", StringType, nullable = true),
    StructField("CVE_data_meta", StructType(Seq(
      StructField("ID", StringType, nullable = true),
      StructField("ASSIGNER", StringType, nullable = true)
    )), nullable = true),
    StructField("problemtype", StructType(Seq(
      StructField("problemtype_data", ArrayType(StructType(Seq(
        StructField("description", ArrayType(StructType(Seq(
          StructField("lang", StringType, nullable = true),
          StructField("value", StringType, nullable = true)
        ))), nullable = true)
      ))), nullable = true)
    )), nullable = true),
    StructField("references", StructType(Seq(
      StructField("reference_data", ArrayType(StructType(Seq(
        StructField("url", StringType, nullable = true),
        StructField("name", StringType, nullable = true),
        StructField("refsource", StringType, nullable = true),
        StructField("tags", ArrayType(StringType), nullable = true)
      ))), nullable = true)
    )), nullable = true),
    StructField("description", StructType(Seq(
      StructField("description_data", ArrayType(StructType(Seq(
        StructField("lang", StringType, nullable = true),
        StructField("value", StringType, nullable = true)
      ))), nullable = true)
    )), nullable = true)
  )), nullable = true),
  StructField("configurations", StructType(Seq(
    StructField("CVE_data_version", StringType, nullable = true),
    StructField("nodes", ArrayType(StructType(Seq(
      StructField("operator", StringType, nullable = true),
      StructField("children", ArrayType(StructType(Seq(
        StructField("children", ArrayType(StringType), nullable = true),
        StructField("cpe_match", ArrayType(StructType(Seq(
          StructField("cpe23Uri", StringType, nullable = true),
          StructField("cpe_name", ArrayType(StringType), nullable = true),
          StructField("versionStartIncluding", StringType, nullable = true),
          StructField("versionEndIncluding", StringType, nullable = true),
          StructField("versionStartExcluding", StringType, nullable = true),
          StructField("versionEndExcluding", StringType, nullable = true),
          StructField("vulnerable", BooleanType, nullable = true)
        ))), nullable = true)
      ))), nullable = true),
      StructField("cpe_match", ArrayType(StructType(Seq(
        StructField("cpe23Uri", StringType, nullable = true),
        StructField("cpe_name", ArrayType(StringType), nullable = true),
        StructField("versionStartIncluding", StringType, nullable = true),
        StructField("versionEndIncluding", StringType, nullable = true),
        StructField("versionStartExcluding", StringType, nullable = true),
        StructField("versionEndExcluding", StringType, nullable = true),
        StructField("vulnerable", BooleanType, nullable = true)
      ))), nullable = true)
    ))), nullable = true)
  )), nullable = true),
  StructField("impact", StructType(Seq(
    StructField("baseMetricV3", StructType(Seq(
      StructField("cvssV3", StructType(Seq(
        StructField("version", StringType, nullable = true),
        StructField("vectorString", StringType, nullable = true),
        StructField("attackVector", StringType, nullable = true),
        StructField("attackComplexity", StringType, nullable = true),
        StructField("privilegesRequired", StringType, nullable = true),
        StructField("userInteraction", StringType, nullable = true),
        StructField("scope", StringType, nullable = true),
        StructField("confidentialityImpact", StringType, nullable = true),
        StructField("integrityImpact", StringType, nullable = true),
        StructField("availabilityImpact", StringType, nullable = true),
        StructField("baseScore", DoubleType, nullable = true),
        StructField("baseSeverity", StringType, nullable = true)
      )), nullable = true),
      StructField("exploitabilityScore", DoubleType, nullable = true),
      StructField("impactScore", DoubleType, nullable = true)
    )), nullable = true)
  )), nullable = true),
  StructField("publishedDate", StringType, nullable = true),
  StructField("lastModifiedDate", StringType, nullable = true)
)))


val spark = SparkSession.builder()
  .appName("JSON to MongoDB")
  .master("local[*]")
  .config("spark.mongodb.write.connection.uri", "mongodb+srv://romain24mezghenna01:<db_password>@cluster0.b619b.mongodb.net/")
  .getOrCreate()


val df_2024 = spark.read
  .schema(StructType(Seq(StructField("CVE_Items", cveSchema, nullable = true)))) 
  .format("json")
  .option("multiline", "true")
  .load("dbfs:/FileStore/shared_uploads/romain24.mezghenna01@gmail.com/nvdcve_1_1_2024.json")

val df_2023 = spark.read
  .schema(StructType(Seq(StructField("CVE_Items", cveSchema, nullable = true))))
  .format("json")
  .option("multiline", "true")
  .load("dbfs:/FileStore/shared_uploads/romain24.mezghenna01@gmail.com/nvdcve_1_1_2023.json")


val extracted_2024 = df_2024.select(explode(col("CVE_Items")).as("CVE"))
val extracted_2023 = df_2023.select(explode(col("CVE_Items")).as("CVE"))


extracted_2024.show(10, truncate = false)
extracted_2023.show(10, truncate = false)


extracted_2024.write
  .format("mongodb")
  .option("database", "CVE")  
  .option("collection", "cve_2024") 
  .mode("append") 
  .save()

extracted_2023.write
  .format("mongodb")
  .option("database", "CVE") 
  .option("collection", "cve_2023")
  .mode("append") 
  .save()

println("Données CVE insérées avec succès dans MongoDB Atlas!")
spark.stop()