extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Type, TypeArray};

fn has_discriminants(
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,
) -> bool {
    #[allow(unused_variables)]
    let has_discriminant = variants.iter().any(|v| {
        if let Some(discriminant) = &v.discriminant {
            true // Return true to indicate that there's at least one variant with a discriminant
        } else {
            false // No discriminant in this variant
        }
    });

    has_discriminant
}

#[proc_macro_derive(ReadSSH)]
pub fn derive_read_ssh(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident;

    let expanded = match input.data {
        Data::Struct(ref data) => {
            match data.fields {
                Fields::Named(ref fields) => {
                    let field_readers = fields.named.iter().map(|f| {
                        let field_name = &f.ident;
                        let field_type = &f.ty;

                        if let Type::Array(TypeArray { elem, len, .. }) = field_type {
                            quote! {
                                let #field_name = <[#elem; #len]>::read_ssh(&mut reader)?;
                            }
                        } else {
                            quote! {
                                let #field_name = <#field_type>::read_ssh(&mut reader)?;
                            }
                        }
                    });
                    let field_names = fields.named.iter().map(|f| f.ident.as_ref().unwrap());

                    quote! {
                        impl ReadSSH for #struct_name {
                            fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
                                #(#field_readers)*
                                Ok(#struct_name { #(#field_names),* })
                            }
                        }
                    }
                }
                Fields::Unnamed(ref _fields) => {
                    // Handle tuple structs (unnamed _fields)
                    unimplemented!();
                }
                Fields::Unit => {
                    // Handle unit structs
                    unimplemented!();
                }
            }
        }
        Data::Enum(ref data) if has_discriminants(&data.variants) => {
            let variant_matches = data.variants.iter().map(|v| {
                let variant = &v.ident;
                let discriminant = v.discriminant.as_ref().map(|(_, expr)| quote! { #expr });
                quote! {
                    #discriminant => Ok(#struct_name::#variant),
                }
            });

            quote! {
                impl ReadSSH for #struct_name {
                    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
                        let code = u32::read_ssh(&mut reader)?;
                        match code {
                            #( #variant_matches )*
                            // _ => unimplemented!(),
                            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid enum discriminant"))
                        }
                    }
                }
            }
        }
        Data::Enum(ref data) if !has_discriminants(&data.variants) => {
            // Code for enums without discriminants, using string names
            let variant_matches = data.variants.iter().map(|v| {
                let variant = &v.ident;
                // Apply the same transformation as in WriteSSH for consistent matching
                let variant_str = variant.to_string().replace("__", "-"); 

                if !variant.to_string().contains("Unknown") { // Check original ident string for "Unknown"
                    quote! {
                        name if name == #variant_str => Ok(#struct_name::#variant),
                    }
                } else {
                    quote! {
                        name => Ok(#struct_name::Unknown(name.to_string())),
                    }
                }
            });

            quote! {
                impl ReadSSH for #struct_name {
                    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
                        let variant_name = String::read_ssh(&mut reader)?;
                        match variant_name.as_str() {
                            #( #variant_matches )*
                            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid enum variant name"))
                        }
                    }
                }
            }
        }
        _ => unimplemented!(), // For now, we're not handling enums or unions
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(WriteSSH)]
pub fn derive_write_ssh(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = input.ident;

    let gen = match input.data {
        Data::Struct(data_struct) => match data_struct.fields {
            Fields::Named(fields) => {
                let field_writers = fields.named.iter().map(|f| {
                    let field_name = &f.ident;
                    quote! {
                        #field_name.write_ssh(writer)?;
                    }
                });
                quote! {
                    impl WriteSSH for #struct_name {
                        fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                            #struct_name::MAGIC.write_ssh(writer)?;
                            #(self.#field_writers)*
                            Ok(())
                        }
                    }
                }
            }
            Fields::Unnamed(fields) => {
                let field_writers = fields.unnamed.iter().enumerate().map(|(i, _)| {
                    let index = syn::Index::from(i);
                    quote! {
                        self.#index.write_ssh(writer)?;
                    }
                });
                quote! {
                    impl WriteSSH for #struct_name {
                        fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                            #(#field_writers)*
                            Ok(())
                        }
                    }
                }
            }
            Fields::Unit => {
                quote! {
                    impl WriteSSH for #struct_name {
                        fn write_ssh<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
                            Ok(())
                        }
                    }
                }
            }
        },
        Data::Enum(data) if has_discriminants(&data.variants) => {
            let variant_matches = data.variants.iter().map(|v| {
                let variant = &v.ident;
                let discriminant = v.discriminant.as_ref().map(|(_, expr)| quote! { #expr });
                quote! {
                    #struct_name::#variant => #discriminant.write_ssh(writer),
                }
            });

            quote! {
                impl WriteSSH for #struct_name {
                    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                        match self {
                            #(#variant_matches)*
                            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid enum variant name"))
                        }
                    }
                }
            }
        }
        Data::Enum(data) if !has_discriminants(&data.variants) => {
            let variant_matches = data.variants.iter().map(|v| {
                let variant_ident = &v.ident;
                let variant_name_str = variant_ident.to_string();

                if variant_name_str == "Unknown" {
                    match &v.fields {
                        Fields::Unnamed(fields_unnamed) if fields_unnamed.unnamed.len() == 1 => {
                            // Assumes the single field is the string to be written
                            // The `ref val` part will bind the inner value of the enum variant
                            quote! {
                                #struct_name::#variant_ident(ref val) => val.write_ssh(writer),
                            }
                        }
                        _ => {
                            // Fallback for Unknown variants that are not Unknown(String)
                            // This could either serialize the "Unknown" name or error.
                            // For now, let's make it error out, or serialize its name if it's a unit variant.
                            // If it's a unit variant Unknown, serialize its name.
                            if matches!(v.fields, Fields::Unit) {
                                let unknown_variant_name_literal = variant_name_str.replace("__", "-");
                                quote! {
                                    #struct_name::#variant_ident => #unknown_variant_name_literal.write_ssh(writer),
                                }
                            } else {
                                // For Unknown variants that are not simple Unit or Unnamed(String)
                                quote! {
                                    #struct_name::#variant_ident(..) => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Cannot serialize complex Unknown variant")),
                                }
                            }
                        }
                    }
                } else {
                    let variant_name_literal = variant_name_str.replace("__", "-");
                    quote! {
                        #struct_name::#variant_ident => #variant_name_literal.to_string().write_ssh(writer),
                    }
                }
            });

            // let mut has_unknown_catch_all = false;
            // for v in data.variants.iter() {
            //     if v.ident.to_string() == "Unknown" {
            //         if let Fields::Unnamed(fields_unnamed) = &v.fields {
            //             if fields_unnamed.unnamed.len() == 1 {
            //                 has_unknown_catch_all = true;
            //                 break;
            //             }
            //         }
            //     }
            // }

            // If there isn't an Unknown(String) variant, we add a default error case.
            // Otherwise, the Unknown(String) variant acts as the catch-all for strings.
            // let default_case = if !has_unknown_catch_all {
            //     quote! { _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Unmatched enum variant for WriteSSH")), }
            // } else {
            //     // If an Unknown(String) variant exists, other non-matching variants should still error.
            //     // The generated match arms should cover all defined variants.
            //     // A specific unit `Unknown` would be handled by its own arm.
            //     // This is tricky because `Unknown(String)` is for deserializing arbitrary strings,
            //     // but for serializing, we only care about the specific variants defined.
            //     // The match should be exhaustive for defined variants.
            //     // The provided example has `MyEnum::Unknown(s) => s.write_ssh(writer),` and no other catch-all.
            //     // This implies the match should be exhaustive over *known* variants + the special Unknown(String).
            //     // So, if all other variants are explicitly matched, what would `_` catch?
            //     // It would catch nothing if all variants are handled.
            //     // Let's ensure all variants are explicitly handled.
            //     // The `variant_matches` should cover all cases.
            //     // If there's an `Unknown(String)` it's handled. If there's a unit `Unknown`, it's handled.
            //     // Other variants are handled.
            //     // So, a generic `_` might only be needed if some variants were filtered out, which they aren't.
            //     // However, if an enum has `Unknown(Foo)` and `Unknown(Bar)`, the logic above only handles one.
            //     // The current logic only handles one `Unknown(String)` like variant.
            //     // The fallback error is good.
            //      quote! { _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Enum variant not serializable as string (and not Unknown(String))")), }
            // };

            quote! {
                impl WriteSSH for #struct_name {
                    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                        match self {
                            #( #variant_matches )*
                            // The default case is now more nuanced.
                            // If all variants are covered by variant_matches, this _ might not be needed
                            // or could be a specific error for truly unexpected states.
                            // For enums like KeyExchangeMethod where Unknown(String) is a valid state to serialize.
                            // The logic above for variant_matches tries to create an arm for each variant.
                            // If there's an Unknown(String) variant, its arm is `Enum::Unknown(ref val) => val.write_ssh(writer)`.
                            // This means the `_` arm below would only be hit if `variant_matches` somehow doesn't cover all variants.
                            // This should ideally be an exhaustive match.
                            // The problem description implies Unknown(s) is one of the match arms, not a catch-all.
                            // So the _ should only be for truly unexpected variants not defined in the enum.
                            // But match self should be exhaustive.
                            // Let's remove the catch-all _ if all variants are handled by `variant_matches`.
                            // The default_case logic above is trying to decide if a catch-all is needed.
                            // For now, let's keep a generic error for safety, as the logic for `variant_matches` might not be perfect.
                            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unhandled enum variant in WriteSSH (should be exhaustive)"))
                        }
                    }
                }
            }
        }
        _ => panic!("WriteSSH can only be derived for structs"),
    };

    // // Debug print
    // eprintln!("CODE: {:?}", gen.to_string());

    gen.into()
}
