extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

#[proc_macro_derive(ReadSSH)]
pub fn derive_read_ssh(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let struct_name = input.ident;
    let fields = if let syn::Data::Struct(s) = input.data {
        s.fields
    } else {
        // Return some error as it's not a struct
        unimplemented!();
    };

    // Collect field names and field readers
    let (field_names, field_readers): (Vec<_>, Vec<_>) = fields.iter().map(|f| {
        let field_name = f.ident.as_ref().unwrap();
        let field_type = &f.ty;
        let reader = quote! {
            let #field_name = #field_type::read_ssh(&mut reader)?;
        };
        (field_name, reader)
    }).unzip();

    // Generate the implementation
    let expanded = quote! {
        impl ReadSSH for #struct_name {
            fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
                #(#field_readers)*
                Ok(#struct_name { #(#field_names),* })
            }
        }
    };

    TokenStream::from(expanded)
}