extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields, Variant};

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
                        quote! {
                            let #field_name = #field_type::read_ssh(&mut reader)?;
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
        Data::Enum(ref data) => {
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
        Data::Enum(data_enum) => {
            let variants = data_enum.variants.iter().enumerate().map(|(index, variant)| {
                let variant_name = &variant.ident;
                let val = index as u32 + 1; // Assuming enum variant values start from 1
                match &variant.fields {
                    Fields::Unit => {
                        quote! {
                            #struct_name::#variant_name => #val.write_ssh(writer),
                        }
                    },
                    // Handle other variant types if necessary
                    _ => unimplemented!(),
                }
            });

            quote! {
                impl WriteSSH for #struct_name {
                    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
                        match self {
                            #(#variants)*
                        }
                    }
                }
            }
        },
        _ => panic!("WriteSSH can only be derived for structs"),
    };

    gen.into()
}
