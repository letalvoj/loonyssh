import scala.io.Source

import java.io._

val url = "https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL"
val namePrefix = "Ssh"
val out = s"src/main/scala/in.vojt.loonyssh/$namePrefix.scala"

val pw = new PrintWriter(new File(out))

val supportedTypes = Map(
    "uint32" -> "Int",
    "int" -> "Int",
    "string" -> "String",
    "..." -> "vararg",
    "bool" -> "Boolean",
    "char" -> "Char",
    "boolean" -> "Boolean",
    "uint64" -> "Long",
    "byte" -> "Byte",
    "byte[]" -> "Array[Byte]",
    "string[]" -> "String[Byte]",
)

def process(stream:List[String], constants:List[(String,String)]):Unit = stream match
    case h :: t if h contains "#define" =>
        pw.println("// "+h)
        parseDefine(h) match
            case Some(define) => process(t, define :: constants)
            case _            => process(t, constants)
    case h :: t if h matches "^\\s+[a-z0-9\\[\\]]+\\s+[0-9A-Z_]+"   =>
        pw.println("// "+h)
        val (m,r) = parseClass(t, parseName(h), Nil)
        pw.println(s"\n$m\n")
        process(r, constants)
    case h :: t  => 
        pw.println("// "+h)
        process(t, constants)
    case _ =>
        pw.println(s"""
        |trait ${namePrefix.capitalize}Msg(val id:Int)
        |object ${namePrefix.capitalize}Constants:
        |${constants.map{case(name, value) => s"  val $name = $value"}.mkString("\n")}
        |""".stripMargin)

def parseClass(stream:List[String], name:String, params:List[(String,String)]):(String, List[String]) = stream match
    case h :: t if h matches "^\t.*"   => 
        pw.println("// "+h)
        parseClass(t,name,parseParam(h) :: params)
    case _  =>
        (composeCaseClass(name, params.reverse), stream)

def composeCaseClass(name:String, params:List[(String,String)]):String =
    val typedParams = params.map{ case (name, typ) => s"$name: ${typ}" }.mkString(", ")
    s"case class ${className(name)}($typedParams) extends ${namePrefix}Msg(${namePrefix}Constants.$name)"

def className(arr:String):String = arr.split('_').map(_.toLowerCase.capitalize).mkString

def paramName(arr:Seq[String]):String = 
    arr.toList match
        case h :: t => h + t.map(_.capitalize).mkString

def parseDefine(line:String):Option[(String, String)] =
    line.trim.split("\\s+") match
        case Array(_, name, value:_*) => Some((name, value.head))
        case _                        => None

def parseParam(line:String):(String, String) =
    if line contains "..." then
        ("...","...")
    else
        val Array(typ,name:_*) = line.trim.split("\\s+")
        if name.last contains "optional"
            (paramName(name.init), s"Option[${supportedTypes(typ)}]")
        else
            println(typ)
            (paramName(name), supportedTypes(typ))

def parseName(line:String):String =
    val (name,_) = parseParam(line)
    name

def psvm() =
    val lines = Source.fromURL(url).getLines.toList
    
    process(lines, List.empty)
    pw.flush()
    pw.close()
    