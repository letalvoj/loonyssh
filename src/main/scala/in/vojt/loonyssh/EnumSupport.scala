package in.vojt.loonyssh

import scala.deriving._
import scala.compiletime._

case object Product0

trait EnumSupport[E<:Enum]:
    def fromName:Map[String, E]
    def toName:Map[E, String]
    def byName(name:String, params:Product):Option[E]

object EnumSupport:
    inline given values[E<:Enum](using m: Mirror.SumOf[E]) as EnumSupport[E] = new EnumSupport:
        override val fromName = _fromName[E, m.MirroredElemTypes, m.MirroredElemLabels]
        override val toName   = fromName.map((k,v) => (v,k))
        override def byName(name:String, params:Product):Option[E] =
            _byName[E, m.MirroredElemTypes, m.MirroredElemLabels](name, params)

    inline private def _fromName[E<:Enum,T,L]:Map[String, E] = inline erasedValue[(T,L)] match
        case _: (t *: ts, l *: ls) =>
            val key = constValue[l].asInstanceOf[String]
            val mirror = summonInline[Mirror.ProductOf[t]]
            val additional:Map[String,E] =
                try
                    val value = mirror.fromProduct(Product0).asInstanceOf[E]
                    Map(key -> value)
                catch
                    // workaround for https://github.com/lampepfl/dotty/issues/9110
                    // check whether it got fixed from time to time
                    case _:java.lang.IndexOutOfBoundsException => Map.empty

            _fromName[E,ts,ls] ++ additional
        case _: (Unit, Unit) => Map.empty


    inline private def _byName[E<:Enum,T,L](name:String, params:Product):Option[E] = inline erasedValue[(T,L)] match
        case _: (t *: ts, l *: ls) =>
            if constValue[l] == name then
                Some(summonInline[Mirror.ProductOf[t]].fromProduct(params).asInstanceOf[E])
            else
                _byName[E,ts,ls](name, params)
        case _: (Unit, Unit) =>
            None
