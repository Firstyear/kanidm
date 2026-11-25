use std::{
    fs::{self, File, FileTimes},
    io::ErrorKind,
    path::Path,
    time::SystemTime,
};

pub fn touch_file_or_quit<P: AsRef<Path>>(file_path: P) {
    /*
    Attempt to touch the file file_path, will quit the application if it fails for any reason.

    Will also create a new file if it doesn't already exist.
    */

    let file_path: &Path = file_path.as_ref();

    if file_path.exists() {
        let now = SystemTime::now();

        let file_time = FileTimes::new().set_accessed(now).set_modified(now);

        match fs::set_times(file_path, file_time) {
            Ok(()) => debug!(
                "Successfully touched existing file {}, can continue",
                file_path.display()
            ),
            Err(err) => {
                match err.kind() {
                    ErrorKind::PermissionDenied => {
                        // we bail here because you won't be able to write them back...
                        error!(
                            "Permission denied writing to {}, quitting.",
                            file_path.display()
                        )
                    }
                    _ => {
                        error!(
                            ?err,
                            "Failed to write to {} due to error ... quitting.",
                            file_path.display(),
                        )
                    }
                }
                std::process::exit(1);
            }
        }
    } else {
        match File::create(file_path) {
            Ok(_file) => debug!("Successfully touched new file {}", file_path.display()),
            Err(err) => {
                error!(
                    ?err,
                    "Failed to write to {} due to error ... quitting.",
                    file_path.display(),
                );
                std::process::exit(1);
            }
        };
    }
}
