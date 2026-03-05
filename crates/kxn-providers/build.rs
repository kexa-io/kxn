fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[
                "../../proto/tfplugin5.proto",
                "../../proto/tfplugin6.proto",
            ],
            &["../../proto"],
        )?;

    println!("cargo:rerun-if-changed=../../proto/tfplugin5.proto");
    println!("cargo:rerun-if-changed=../../proto/tfplugin6.proto");

    Ok(())
}
