/// Configuration for a single dictionary layer
#[derive(Debug, Clone)]
pub struct LayerConfig {
    pub input_bits: usize,
    pub output_bits: usize,
}

/// Configuration for the multi-layer dictionary
#[derive(Debug, Clone)]
pub struct DictionaryConfig {
    layers: Vec<LayerConfig>,
}

impl DictionaryConfig {
    /// Create a new dictionary configuration with validation
    ///
    /// # Validation Rules
    /// - Minimum 4 layers required
    /// - Each layer must expand: output_bits > input_bits
    pub fn new(layers: Vec<LayerConfig>) -> Result<Self, String> {
        // Validation: minimum 4 layers
        if layers.len() < 4 {
            return Err(format!(
                "Minimum 4 layers required, got {}",
                layers.len()
            ));
        }

        // Validation: each layer must expand
        for (i, cfg) in layers.iter().enumerate() {
            if cfg.output_bits <= cfg.input_bits {
                return Err(format!(
                    "Layer {}: must expand (output > input), got input={}, output={}",
                    i, cfg.input_bits, cfg.output_bits
                ));
            }
        }

        Ok(Self { layers })
    }

    /// Get the default 4-layer configuration
    pub fn default() -> Self {
        Self::new(vec![
            LayerConfig { input_bits: 8, output_bits: 12 },
            LayerConfig { input_bits: 6, output_bits: 9 },
            LayerConfig { input_bits: 4, output_bits: 6 },
            LayerConfig { input_bits: 2, output_bits: 4 },
        ])
        .unwrap()
    }

    /// Get the layers configuration
    pub fn layers(&self) -> &[LayerConfig] {
        &self.layers
    }
}

/// Configuration for encryption options
#[derive(Debug, Clone)]
pub struct EncryptionConfig {
    /// Enable random padding for IND-CPA security (default: true)
    pub randomness: bool,
    /// Enable zstd compression for size optimization (default: true)
    pub compression: bool,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            randomness: true,
            compression: true,
        }
    }
}

impl EncryptionConfig {
    /// Create config with both randomness and compression enabled (recommended)
    pub fn secure() -> Self {
        Self::default()
    }

    /// Create config with only randomness (no compression)
    pub fn randomness_only() -> Self {
        Self {
            randomness: true,
            compression: false,
        }
    }

    /// Create config with only compression (no randomness)
    /// Warning: Not IND-CPA secure!
    pub fn compression_only() -> Self {
        Self {
            randomness: false,
            compression: true,
        }
    }

    /// Create config with no randomness or compression (basic mode)
    /// Warning: Not IND-CPA secure and no size optimization!
    pub fn basic() -> Self {
        Self {
            randomness: false,
            compression: false,
        }
    }
}
