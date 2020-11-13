//// macro na vytazeni rodice z tridy ...
//
//import scala.quoted._
//import scala.tasty._
//
//// https://dotty.epfl.ch/docs/reference/metaprogramming/tasty-reflect.html
//
//import scala.quoted._
//
//inline def power[T]: Unit = ${ powerImpl[T] }
//
//private def powerImpl[T](using ctx:QuoteContext, tt:Type[T]): Expr[Unit] =
//  println(tt.unseal)
//  '{()}