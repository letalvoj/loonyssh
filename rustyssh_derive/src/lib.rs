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
                let variant_str = variant.to_string();

                if !variant_str.contains("Unknown") {
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
                let variant = &v.ident;
                let variant_str = variant.to_string().replace("__", "-");

                if !variant_str.contains("Unknown") {
                    quote! {
                        #struct_name::#variant => #variant_str.write_ssh(writer),
                    }
                } else {
                    quote! {}
                }
            });

            quote! {
                impl WriteSSH for #struct_name {
                    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                        match self {
                            #( #variant_matches )*
                            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid enum variant name"))
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
