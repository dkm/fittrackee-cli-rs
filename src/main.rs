/*
 * This file is part of the Fittrackee-cli-rs application (https://github.com/dkm/fittrackee-cli-rs)
 * Copyright (c) 2023 Marc Poulhiès <dkm@kataplop.net>.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

use clap::parser::ValueSource;
use clap::{arg, Command as ClapCommand};
use fitparser::profile::field_types::MesgNum;
use fitparser::Value;
use reqwest::header::AUTHORIZATION;
use reqwest::{multipart, Body};
use serde::Deserialize;
use std::collections::HashMap;
use std::process::Command;
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};

trait WorkoutSource {
    fn get_gpx_filepath(&self) -> &str;
    fn get_activity(&self) -> &str;
}

struct Workout {
    gpxfile: Option<String>,
    fitfile: Option<String>,
    activity: Option<String>,
}

impl Drop for Workout {
    fn drop(&mut self) {
        if self.fitfile.is_some() {
            println!("> Dropping {}", self.gpxfile.as_ref().unwrap());
        }
    }
}

impl Workout {
    fn from_gpx(gpxfile: &str, activity: &str) -> Result<Self, Error> {
        Ok(Workout {
            gpxfile: Some(String::from(gpxfile)),
            fitfile: None,
            activity: Some(String::from(activity)),
        })
    }

    fn from_fit(fitfile: &str) -> Result<Self, Error> {
        let mut file = std::fs::File::open(fitfile)?;
        let mut activity = None;

        println!("FIT parsed");
        for data in fitparser::from_reader(&mut file)? {
            if data.kind() == MesgNum::Sport {
                for field in data.into_vec() {
                    if field.name().eq("name") {
                        if let Value::String(s) = field.value() {
                            activity = Some(s.clone())
                        }
                    }
                }
            }
        }
        let tmpfile = NamedTempFile::new()?;
        let (_, path) = tmpfile.keep()?;

        Command::new("gpsbabel")
            .args([
                "-i",
                "garmin_fit",
                "-f",
                fitfile,
                "-o",
                "gpx",
                "-F",
                path.as_path().to_str().ok_or(Error::CatchAllError)?,
            ])
            .output()
            .expect("failed to execute process");

        Ok(Workout {
            gpxfile: Some(String::from(
                path.as_path().to_str().ok_or(Error::CatchAllError)?,
            )),
            fitfile: Some(String::from(fitfile)),
            activity,
        })
    }
}

impl WorkoutSource for Workout {
    fn get_gpx_filepath(&self) -> &str {
        self.gpxfile.as_ref().unwrap()
    }

    fn get_activity(&self) -> &str {
        self.activity.as_ref().unwrap()
    }
}

#[derive(Deserialize, Debug)]
struct Trackee {
    token: String,
    sport_map: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct Sport {
    color: Option<u8>,
    id: u8,
    is_active: bool,
    is_active_for_user: bool,
    label: String,
    stopped_speed_threshold: f32,
}

#[derive(Deserialize, Debug)]
struct OnlySport {
    sports: Vec<Sport>,
}

#[derive(Deserialize, Debug)]
struct FittrackeeResponse<T> {
    data: T,
    status: String,
}

type RSports = FittrackeeResponse<OnlySport>;

#[derive(Deserialize, Debug)]
struct Credential {
    username: String,
    password: String,
}

#[derive(Debug, Error)]
enum Error {
    #[error("Unknown sport")]
    UnknownSport,

    #[error("Catchall error")]
    CatchAllError,

    #[error("Reqwest error")]
    ReqwestError {
        #[from]
        source: reqwest::Error,
    },
    #[error("IO error")]
    IoError {
        #[from]
        source: std::io::Error,
    },

    #[error("Serde error")]
    SerdeError {
        #[from]
        source: serde_json::Error,
    },

    #[error("FIT parser error")]
    FITParserError {
        #[from]
        source: fitparser::Error,
    },

    #[error("tempfile error")]
    TempfileError {
        #[from]
        source: tempfile::PersistError,
    },
}

impl Trackee {
    async fn login(login: &str, password: &str) -> Result<Trackee, Error> {
        let sport_data = std::fs::read_to_string("./map.json").expect("Unable to read file");

        let sport_map =
            serde_json::from_str(&sport_data).expect("JSON does not have correct format.");
        println!("{:?}", sport_map);

        let mut map = HashMap::new();
        map.insert("email", login);
        map.insert("password", password);

        let client = reqwest::Client::new();
        let resp = client
            .post("http://localhost:5000/api/auth/login")
            .json(&map)
            .send()
            .await?
            .json::<HashMap<String, String>>()
            .await?;

        let token = resp.get("auth_token").unwrap();
        println!("{}", token);

        Ok(Trackee {
            token: token.clone(),
            sport_map,
        })
    }

    async fn add_workout(&self, workout: &Workout, notes: &str) -> Result<(), Error> {
        let sport_name = workout.get_activity();
        let sport_id = self
            .get_sport_id(sport_name)
            .await
            .ok_or(Error::UnknownSport)?;

        println!("Found {}:{}", sport_name, sport_id);
        let file = File::open(workout.get_gpx_filepath()).await?;

        // read file body stream
        let stream = FramedRead::new(file, BytesCodec::new());
        let file_body = Body::wrap_stream(stream);

        //make form part of file
        let some_file = multipart::Part::stream(file_body)
            .file_name("test.gpx")
            .mime_str("text/plain")?;

        let form = multipart::Form::new()
            .text(
                "data",
                format!("{{\"sport_id\" : {}, \"notes\": \"{}\" }}", sport_id, notes),
            )
            .part("file", some_file);

        let client = reqwest::Client::new();
        let resp = client
            .post("http://localhost:5000/api/workouts")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .multipart(form)
            .build()?;

        let _resp = client.execute(resp).await?;

        Ok(())
    }

    async fn get_sport_id(&self, sport_name: &str) -> Option<u8> {
        println!("Get sport for {}", sport_name);

        let lookup = if self.sport_map.contains_key(sport_name) {
            self.sport_map.get(sport_name).unwrap()
        } else {
            sport_name
        };
        println!("-> found: {}", lookup);

        self.get_sports()
            .await
            .ok()?
            .into_iter()
            .find(|x| x.label.eq(lookup))
            .map(|x| x.id)
    }

    async fn get_sports(&self) -> Result<Vec<Sport>, Error> {
        let client = reqwest::Client::new();
        let resp = client
            .get("http://localhost:5000/api/sports")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await?;

        let resp = resp.json::<RSports>().await?;
        Ok(resp.data.sports)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = ClapCommand::new("fittrackee-rs")
        .version("0.1")
        .author("Marc Poulhiès <dkm@kataplop.net>")
        .about("Upload to fittrackee")
        .args(&[
            arg!(--credentials <FILE> "Credentials file"),
            arg!(--fit <FIT> "FIT file"),
            arg!(--gpx <GPX> "GPX file"),
            arg!(--sport <SPORT> "Sport Name"),
            arg!(--notes <notes> "Notes"),
            arg!(--"no-connect" "Do not connect"),
        ])
        .get_matches();

    let workout = if let Some(fit_file) = matches.get_one::<String>("fit") {
        Workout::from_fit(fit_file)?
    } else {
        let gpx_file = matches.get_one::<String>("gpx").unwrap();
        let sport_name = matches.get_one::<String>("sport").unwrap();
        Workout::from_gpx(gpx_file, sport_name)?
    };

    let notes = matches.get_one::<String>("notes").unwrap();

    if matches.value_source("no-connect") == Some(ValueSource::CommandLine) {
        println!("Not doing anything remotely");
    } else {
        let cred_file = matches.get_one::<String>("credentials").unwrap();

        let cred_data = std::fs::read_to_string(cred_file).expect("Unable to read file");

        let creds: Credential =
            serde_json::from_str(&cred_data).expect("JSON does not have correct format.");

        println!("Adding workout");
        let trackee = Trackee::login(&creds.username, &creds.password)
            .await
            .unwrap();

        for s in trackee.get_sports().await?.into_iter().map(|x| x.label) {
            println!("sport : {}", s);
        }

        trackee.add_workout(&workout, notes).await?;
    }
    Ok(())
}
