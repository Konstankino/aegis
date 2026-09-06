# Cross-compile the extension and stage the layer contents, then zip layer + handler.

resource "null_resource" "build_extension" {
  triggers = {
    src_hash   = local.extension_src_hash
    arch       = var.architecture
    build_hash = filesha1("${path.module}/build.sh")
  }

  provisioner "local-exec" {
    command = "bash ${path.module}/build.sh"
    environment = {
      AEGIS_ARCH      = var.architecture
      AEGIS_WORKSPACE = local.workspace_dir
      AEGIS_STAGING   = local.staging_dir
    }
  }
}

# Zip the staged extension + policies into the layer artifact. `depends_on` defers this data
# source until after the build has run.
data "archive_file" "layer" {
  type        = "zip"
  source_dir  = local.staging_dir
  output_path = "${path.module}/build/aegis-extension-layer.zip"

  depends_on = [null_resource.build_extension]
}

# The Python handler needs no build (standard library only).
data "archive_file" "handler" {
  type        = "zip"
  source_dir  = "${path.module}/handler"
  output_path = "${path.module}/build/handler.zip"
}
