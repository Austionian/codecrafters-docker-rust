use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::fs::copy;
use std::io::{Cursor, Seek, SeekFrom, Write};
use std::os::unix::fs;
use tar::Archive;

#[derive(serde::Deserialize)]
struct Token {
    token: String,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ManifestList {
    schema_version: u8,
    media_type: String,
    // The manifests field contains a list of manifests for specific platforms.
    config: Config,
    // The layer list is ordered starting from the base image (opposite order of schema1).
    layers: Vec<Layer>,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Config {
    // The MIME type of the referenced object. This will generally be application/vnd.docker.distribution.manifest.v2+json.
    media_type: String,
    // The size in bytes of the object. This field exists so that a client will have an expected size for the content before validating. If the length of the retrieved content does not match the specified length, the content should not be trusted.
    size: usize,
    // The digest of the content, as defined by the Registry V2 HTTP API Specificiation.
    digest: String,
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Layer {
    // The MIME type of the referenced object. This will generally be application/vnd.docker.distribution.manifest.v2+json.
    media_type: String,
    // The size in bytes of the object. This field exists so that a client will have an expected size for the content before validating. If the length of the retrieved content does not match the specified length, the content should not be trusted.
    size: usize,
    // The digest of the content, as defined by the Registry V2 HTTP API Specificiation.
    digest: String,
    // Provides a list of URLs from which the content may be fetched. Content must be verified against the digest and size. This field is optional and uncommon.
    urls: Option<Vec<String>>,
}

async fn get_token(image: &str) -> Result<String> {
    Ok(reqwest::get(format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/{}:pull",
        image
    ))
    .await?
    .json::<Token>()
    .await?
    .token)
}

async fn get_manifest(image: &str, token: &str) -> Result<ManifestList> {
    let client = reqwest::Client::new();
    Ok(client
        .get(format!(
            "https://registry.hub.docker.com/v2/library/{}/manifests/latest",
            image
        ))
        .header(reqwest::header::AUTHORIZATION, &format!("Bearer {}", token))
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await?
        .json::<ManifestList>()
        .await?)
}

async fn download_image(image: &str) -> Result<()> {
    let token = get_token(image).await?;
    let manifest = get_manifest(image, &token).await?;

    let client = reqwest::Client::new();
    for layer in manifest.layers.iter() {
        let blob = client
            .get(format!(
                "https://registry.hub.docker.com/v2/library/{}/blobs/{}",
                image, layer.digest
            ))
            .header(reqwest::header::AUTHORIZATION, &format!("Bearer {}", token))
            .header("Accept", &layer.media_type)
            .send()
            .await?
            .bytes()
            .await?;

        let mut bytes = Cursor::new(blob);

        let mut file = tempfile::tempfile()?;

        std::io::copy(&mut bytes, &mut file)?;

        file.seek(SeekFrom::Start(0))?;

        let decoded = GzDecoder::new(file);

        Archive::new(decoded).unpack("temp")?;
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    let image = &args[2];
    let command = &args[3];
    let command_args = &args[4..];

    std::fs::create_dir_all("temp/usr/local/bin")?;
    copy(
        "/usr/local/bin/docker-explorer",
        "temp/usr/local/bin/docker-explorer",
    )?;

    download_image(image).await?;

    fs::chroot("temp")?;
    std::env::set_current_dir("/")?;
    std::fs::create_dir_all("dev/null")?;

    #[cfg(target_os = "linux")]
    unsafe {
        libc::unshare(libc::CLONE_NEWPID);
    }

    let output = std::process::Command::new(command)
        .args(command_args)
        .output()
        .with_context(|| {
            format!(
                "Tried to run '{}' with arguments {:?}",
                command, command_args
            )
        })?;

    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;

    if output.status.success() {
        std::process::exit(0);
    } else {
        std::process::exit(output.status.code().unwrap());
    }
}
