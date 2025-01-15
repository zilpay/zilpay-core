use errors::qrcode::QRCodeError;
use fast_qr::convert::image::ImageBuilder;
use fast_qr::convert::{svg::SvgBuilder, Builder, Shape};
use fast_qr::qr::QRBuilder;
use fast_qr::ECL;

#[derive(Debug, Clone)]
pub struct QrConfig {
    pub size: u32,
    pub gapless: bool,
    pub color: u32,
    pub eye_shape: EyeShape,
    pub data_module_shape: DataModuleShape,
}

#[derive(Debug, Clone)]
pub enum EyeShape {
    Square,
    Circle,
}

#[derive(Debug, Clone)]
pub enum DataModuleShape {
    Square,
    Circle,
}

impl From<u8> for EyeShape {
    fn from(value: u8) -> Self {
        match value {
            0 => EyeShape::Square,
            1 => EyeShape::Circle,
            _ => EyeShape::Square,
        }
    }
}

impl From<u8> for DataModuleShape {
    fn from(value: u8) -> Self {
        match value {
            0 => DataModuleShape::Square,
            1 => DataModuleShape::Circle,
            _ => DataModuleShape::Circle,
        }
    }
}

impl From<EyeShape> for u8 {
    fn from(value: EyeShape) -> Self {
        match value {
            EyeShape::Square => 0,
            EyeShape::Circle => 1,
        }
    }
}

impl From<DataModuleShape> for u8 {
    fn from(value: DataModuleShape) -> Self {
        match value {
            DataModuleShape::Square => 0,
            DataModuleShape::Circle => 1,
        }
    }
}

pub fn flutter_to_rgba(color: u32) -> [u8; 4] {
    [
        ((color >> 16) & 0xFF) as u8, // R
        ((color >> 8) & 0xFF) as u8,  // G
        (color & 0xFF) as u8,         // B
        ((color >> 24) & 0xFF) as u8, // A
    ]
}

pub fn generate_qr_svg(data: &str, config: QrConfig) -> Result<String, QRCodeError> {
    let qr = QRBuilder::new(data)
        .ecl(ECL::H)
        .build()
        .map_err(|e| QRCodeError::QrcodeGenError(data.to_string(), e.to_string()))?;

    let shape = match config.data_module_shape {
        DataModuleShape::Square => Shape::Square,
        DataModuleShape::Circle => Shape::Circle,
    };
    let module_color = flutter_to_rgba(config.color);

    let svg = SvgBuilder::default()
        .shape(shape)
        .margin(if config.gapless { 0 } else { 4 })
        .module_color(module_color)
        .background_color([255, 255, 255, 0])
        .to_str(&qr);

    Ok(svg)
}

pub fn generate_qr_png(data: &str, config: QrConfig) -> Result<Vec<u8>, QRCodeError> {
    let qr = QRBuilder::new(data)
        .ecl(ECL::H)
        .build()
        .map_err(|e| QRCodeError::QrcodeGenError(data.to_string(), e.to_string()))?;

    let shape = match config.data_module_shape {
        DataModuleShape::Square => Shape::Square,
        DataModuleShape::Circle => Shape::Circle,
    };
    let module_color = flutter_to_rgba(config.color);

    let img = ImageBuilder::default()
        .shape(shape)
        .fit_width(config.size)
        .fit_height(config.size)
        .margin(if config.gapless { 0 } else { 4 })
        .module_color(module_color)
        .background_color([255, 255, 255, 0])
        .to_bytes(&qr)
        .map_err(|e| QRCodeError::QrcodeGenError(data.to_string(), e.to_string()))?;

    Ok(img)
}

#[cfg(test)]
mod tests_qr_code_gen {
    use super::*;

    #[test]
    fn test_qr_themes() {
        let config = QrConfig {
            size: 220,
            gapless: true,
            color: 0xFF8A2BE2,
            eye_shape: EyeShape::Square,
            data_module_shape: DataModuleShape::Circle,
        };

        let address = "test";
        let svg = generate_qr_svg(address, config).unwrap();

        assert_eq!("<svg viewBox=\"0 0 21 21\" xmlns=\"http://www.w3.org/2000/svg\"><rect width=\"21px\" height=\"21px\" fill=\"#ffffff00\"/><path d=\"M1,0.5a.5,.5 0 1,1 0,-.1M2,0.5a.5,.5 0 1,1 0,-.1M3,0.5a.5,.5 0 1,1 0,-.1M4,0.5a.5,.5 0 1,1 0,-.1M5,0.5a.5,.5 0 1,1 0,-.1M6,0.5a.5,.5 0 1,1 0,-.1M7,0.5a.5,.5 0 1,1 0,-.1M9,0.5a.5,.5 0 1,1 0,-.1M10,0.5a.5,.5 0 1,1 0,-.1M11,0.5a.5,.5 0 1,1 0,-.1M13,0.5a.5,.5 0 1,1 0,-.1M15,0.5a.5,.5 0 1,1 0,-.1M16,0.5a.5,.5 0 1,1 0,-.1M17,0.5a.5,.5 0 1,1 0,-.1M18,0.5a.5,.5 0 1,1 0,-.1M19,0.5a.5,.5 0 1,1 0,-.1M20,0.5a.5,.5 0 1,1 0,-.1M21,0.5a.5,.5 0 1,1 0,-.1M1,1.5a.5,.5 0 1,1 0,-.1M7,1.5a.5,.5 0 1,1 0,-.1M9,1.5a.5,.5 0 1,1 0,-.1M10,1.5a.5,.5 0 1,1 0,-.1M15,1.5a.5,.5 0 1,1 0,-.1M21,1.5a.5,.5 0 1,1 0,-.1M1,2.5a.5,.5 0 1,1 0,-.1M3,2.5a.5,.5 0 1,1 0,-.1M4,2.5a.5,.5 0 1,1 0,-.1M5,2.5a.5,.5 0 1,1 0,-.1M7,2.5a.5,.5 0 1,1 0,-.1M11,2.5a.5,.5 0 1,1 0,-.1M12,2.5a.5,.5 0 1,1 0,-.1M15,2.5a.5,.5 0 1,1 0,-.1M17,2.5a.5,.5 0 1,1 0,-.1M18,2.5a.5,.5 0 1,1 0,-.1M19,2.5a.5,.5 0 1,1 0,-.1M21,2.5a.5,.5 0 1,1 0,-.1M1,3.5a.5,.5 0 1,1 0,-.1M3,3.5a.5,.5 0 1,1 0,-.1M4,3.5a.5,.5 0 1,1 0,-.1M5,3.5a.5,.5 0 1,1 0,-.1M7,3.5a.5,.5 0 1,1 0,-.1M9,3.5a.5,.5 0 1,1 0,-.1M12,3.5a.5,.5 0 1,1 0,-.1M13,3.5a.5,.5 0 1,1 0,-.1M15,3.5a.5,.5 0 1,1 0,-.1M17,3.5a.5,.5 0 1,1 0,-.1M18,3.5a.5,.5 0 1,1 0,-.1M19,3.5a.5,.5 0 1,1 0,-.1M21,3.5a.5,.5 0 1,1 0,-.1M1,4.5a.5,.5 0 1,1 0,-.1M3,4.5a.5,.5 0 1,1 0,-.1M4,4.5a.5,.5 0 1,1 0,-.1M5,4.5a.5,.5 0 1,1 0,-.1M7,4.5a.5,.5 0 1,1 0,-.1M9,4.5a.5,.5 0 1,1 0,-.1M12,4.5a.5,.5 0 1,1 0,-.1M15,4.5a.5,.5 0 1,1 0,-.1M17,4.5a.5,.5 0 1,1 0,-.1M18,4.5a.5,.5 0 1,1 0,-.1M19,4.5a.5,.5 0 1,1 0,-.1M21,4.5a.5,.5 0 1,1 0,-.1M1,5.5a.5,.5 0 1,1 0,-.1M7,5.5a.5,.5 0 1,1 0,-.1M9,5.5a.5,.5 0 1,1 0,-.1M10,5.5a.5,.5 0 1,1 0,-.1M15,5.5a.5,.5 0 1,1 0,-.1M21,5.5a.5,.5 0 1,1 0,-.1M1,6.5a.5,.5 0 1,1 0,-.1M2,6.5a.5,.5 0 1,1 0,-.1M3,6.5a.5,.5 0 1,1 0,-.1M4,6.5a.5,.5 0 1,1 0,-.1M5,6.5a.5,.5 0 1,1 0,-.1M6,6.5a.5,.5 0 1,1 0,-.1M7,6.5a.5,.5 0 1,1 0,-.1M9,6.5a.5,.5 0 1,1 0,-.1M11,6.5a.5,.5 0 1,1 0,-.1M13,6.5a.5,.5 0 1,1 0,-.1M15,6.5a.5,.5 0 1,1 0,-.1M16,6.5a.5,.5 0 1,1 0,-.1M17,6.5a.5,.5 0 1,1 0,-.1M18,6.5a.5,.5 0 1,1 0,-.1M19,6.5a.5,.5 0 1,1 0,-.1M20,6.5a.5,.5 0 1,1 0,-.1M21,6.5a.5,.5 0 1,1 0,-.1M10,7.5a.5,.5 0 1,1 0,-.1M11,7.5a.5,.5 0 1,1 0,-.1M13,7.5a.5,.5 0 1,1 0,-.1M4,8.5a.5,.5 0 1,1 0,-.1M7,8.5a.5,.5 0 1,1 0,-.1M10,8.5a.5,.5 0 1,1 0,-.1M12,8.5a.5,.5 0 1,1 0,-.1M16,8.5a.5,.5 0 1,1 0,-.1M17,8.5a.5,.5 0 1,1 0,-.1M18,8.5a.5,.5 0 1,1 0,-.1M20,8.5a.5,.5 0 1,1 0,-.1M21,8.5a.5,.5 0 1,1 0,-.1M4,9.5a.5,.5 0 1,1 0,-.1M5,9.5a.5,.5 0 1,1 0,-.1M8,9.5a.5,.5 0 1,1 0,-.1M9,9.5a.5,.5 0 1,1 0,-.1M13,9.5a.5,.5 0 1,1 0,-.1M15,9.5a.5,.5 0 1,1 0,-.1M16,9.5a.5,.5 0 1,1 0,-.1M20,9.5a.5,.5 0 1,1 0,-.1M21,9.5a.5,.5 0 1,1 0,-.1M1,10.5a.5,.5 0 1,1 0,-.1M3,10.5a.5,.5 0 1,1 0,-.1M4,10.5a.5,.5 0 1,1 0,-.1M7,10.5a.5,.5 0 1,1 0,-.1M8,10.5a.5,.5 0 1,1 0,-.1M9,10.5a.5,.5 0 1,1 0,-.1M11,10.5a.5,.5 0 1,1 0,-.1M13,10.5a.5,.5 0 1,1 0,-.1M15,10.5a.5,.5 0 1,1 0,-.1M16,10.5a.5,.5 0 1,1 0,-.1M17,10.5a.5,.5 0 1,1 0,-.1M18,10.5a.5,.5 0 1,1 0,-.1M19,10.5a.5,.5 0 1,1 0,-.1M21,10.5a.5,.5 0 1,1 0,-.1M1,11.5a.5,.5 0 1,1 0,-.1M2,11.5a.5,.5 0 1,1 0,-.1M4,11.5a.5,.5 0 1,1 0,-.1M10,11.5a.5,.5 0 1,1 0,-.1M13,11.5a.5,.5 0 1,1 0,-.1M15,11.5a.5,.5 0 1,1 0,-.1M16,11.5a.5,.5 0 1,1 0,-.1M17,11.5a.5,.5 0 1,1 0,-.1M18,11.5a.5,.5 0 1,1 0,-.1M20,11.5a.5,.5 0 1,1 0,-.1M21,11.5a.5,.5 0 1,1 0,-.1M1,12.5a.5,.5 0 1,1 0,-.1M2,12.5a.5,.5 0 1,1 0,-.1M6,12.5a.5,.5 0 1,1 0,-.1M7,12.5a.5,.5 0 1,1 0,-.1M9,12.5a.5,.5 0 1,1 0,-.1M10,12.5a.5,.5 0 1,1 0,-.1M11,12.5a.5,.5 0 1,1 0,-.1M16,12.5a.5,.5 0 1,1 0,-.1M18,12.5a.5,.5 0 1,1 0,-.1M20,12.5a.5,.5 0 1,1 0,-.1M21,12.5a.5,.5 0 1,1 0,-.1M9,13.5a.5,.5 0 1,1 0,-.1M12,13.5a.5,.5 0 1,1 0,-.1M13,13.5a.5,.5 0 1,1 0,-.1M14,13.5a.5,.5 0 1,1 0,-.1M17,13.5a.5,.5 0 1,1 0,-.1M18,13.5a.5,.5 0 1,1 0,-.1M20,13.5a.5,.5 0 1,1 0,-.1M21,13.5a.5,.5 0 1,1 0,-.1M1,14.5a.5,.5 0 1,1 0,-.1M2,14.5a.5,.5 0 1,1 0,-.1M3,14.5a.5,.5 0 1,1 0,-.1M4,14.5a.5,.5 0 1,1 0,-.1M5,14.5a.5,.5 0 1,1 0,-.1M6,14.5a.5,.5 0 1,1 0,-.1M7,14.5a.5,.5 0 1,1 0,-.1M10,14.5a.5,.5 0 1,1 0,-.1M11,14.5a.5,.5 0 1,1 0,-.1M12,14.5a.5,.5 0 1,1 0,-.1M15,14.5a.5,.5 0 1,1 0,-.1M17,14.5a.5,.5 0 1,1 0,-.1M20,14.5a.5,.5 0 1,1 0,-.1M1,15.5a.5,.5 0 1,1 0,-.1M7,15.5a.5,.5 0 1,1 0,-.1M10,15.5a.5,.5 0 1,1 0,-.1M11,15.5a.5,.5 0 1,1 0,-.1M13,15.5a.5,.5 0 1,1 0,-.1M15,15.5a.5,.5 0 1,1 0,-.1M20,15.5a.5,.5 0 1,1 0,-.1M1,16.5a.5,.5 0 1,1 0,-.1M3,16.5a.5,.5 0 1,1 0,-.1M4,16.5a.5,.5 0 1,1 0,-.1M5,16.5a.5,.5 0 1,1 0,-.1M7,16.5a.5,.5 0 1,1 0,-.1M12,16.5a.5,.5 0 1,1 0,-.1M14,16.5a.5,.5 0 1,1 0,-.1M15,16.5a.5,.5 0 1,1 0,-.1M18,16.5a.5,.5 0 1,1 0,-.1M21,16.5a.5,.5 0 1,1 0,-.1M1,17.5a.5,.5 0 1,1 0,-.1M3,17.5a.5,.5 0 1,1 0,-.1M4,17.5a.5,.5 0 1,1 0,-.1M5,17.5a.5,.5 0 1,1 0,-.1M7,17.5a.5,.5 0 1,1 0,-.1M9,17.5a.5,.5 0 1,1 0,-.1M10,17.5a.5,.5 0 1,1 0,-.1M12,17.5a.5,.5 0 1,1 0,-.1M16,17.5a.5,.5 0 1,1 0,-.1M18,17.5a.5,.5 0 1,1 0,-.1M20,17.5a.5,.5 0 1,1 0,-.1M21,17.5a.5,.5 0 1,1 0,-.1M1,18.5a.5,.5 0 1,1 0,-.1M3,18.5a.5,.5 0 1,1 0,-.1M4,18.5a.5,.5 0 1,1 0,-.1M5,18.5a.5,.5 0 1,1 0,-.1M7,18.5a.5,.5 0 1,1 0,-.1M13,18.5a.5,.5 0 1,1 0,-.1M14,18.5a.5,.5 0 1,1 0,-.1M16,18.5a.5,.5 0 1,1 0,-.1M19,18.5a.5,.5 0 1,1 0,-.1M21,18.5a.5,.5 0 1,1 0,-.1M1,19.5a.5,.5 0 1,1 0,-.1M7,19.5a.5,.5 0 1,1 0,-.1M10,19.5a.5,.5 0 1,1 0,-.1M12,19.5a.5,.5 0 1,1 0,-.1M15,19.5a.5,.5 0 1,1 0,-.1M16,19.5a.5,.5 0 1,1 0,-.1M18,19.5a.5,.5 0 1,1 0,-.1M1,20.5a.5,.5 0 1,1 0,-.1M2,20.5a.5,.5 0 1,1 0,-.1M3,20.5a.5,.5 0 1,1 0,-.1M4,20.5a.5,.5 0 1,1 0,-.1M5,20.5a.5,.5 0 1,1 0,-.1M6,20.5a.5,.5 0 1,1 0,-.1M7,20.5a.5,.5 0 1,1 0,-.1M11,20.5a.5,.5 0 1,1 0,-.1M12,20.5a.5,.5 0 1,1 0,-.1M14,20.5a.5,.5 0 1,1 0,-.1M16,20.5a.5,.5 0 1,1 0,-.1M18,20.5a.5,.5 0 1,1 0,-.1M19,20.5a.5,.5 0 1,1 0,-.1M20,20.5a.5,.5 0 1,1 0,-.1\" fill=\"#8a2be2\"/></svg>", svg);
    }
}
