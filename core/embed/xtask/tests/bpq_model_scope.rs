//! bpq is a model-scoped feature of T3W1: the resolver hands `bpq` to a T3W1
//! firmware build (hardware and emulator) and to no other model and no other
//! project. Exercises the real resolver over every model xtask can build.

use clap::ValueEnum;
use xtask::args::Project;
use xtask::config::{ModelConfig, resolve_board_features};
use xtask::helpers::workspace_dir;
use xtask::model::Model;

fn has_bpq(features: &[String]) -> bool {
    features.iter().any(|f| f == "bpq")
}

#[test]
fn bpq_resolves_exactly_for_t3w1_firmware() {
    for model in Model::value_variants() {
        let cfg = ModelConfig::load(model.model_id()).unwrap();
        let board = cfg.default_board.clone();
        for emulator in [false, true] {
            let resolved = match resolve_board_features(&cfg, &board, Project::Firmware, emulator) {
                Ok(r) => r,
                // A board without `emulator_header` cannot be emulated; the
                // resolver refuses it by name and that is the only error allowed.
                Err(e) if emulator => {
                    assert!(e.to_string().contains("does not support emulation"), "{e}");
                    continue;
                }
                Err(e) => panic!("{}: {e}", model.model_id()),
            };
            assert_eq!(
                has_bpq(&resolved.features),
                model.model_id() == "T3W1",
                "model {} emulator={emulator}: {:?}",
                model.model_id(),
                resolved.features
            );
        }
    }
}

#[test]
fn bpq_never_reaches_a_non_firmware_project() {
    let cfg = ModelConfig::load("T3W1").unwrap();
    let board = cfg.default_board.clone();
    for project in Project::value_variants() {
        if *project == Project::Firmware {
            continue;
        }
        let resolved = resolve_board_features(&cfg, &board, *project, false).unwrap();
        assert!(
            !has_bpq(&resolved.features),
            "{project:?} on T3W1 got bpq: {:?}",
            resolved.features
        );
    }
}

#[test]
fn bpq_is_declared_only_by_t3w1_model_toml() {
    // Declaration side: a model.toml that adds `bpq` without a ruling fails here.
    for model in Model::value_variants() {
        let cfg = ModelConfig::load(model.model_id()).unwrap();
        assert_eq!(
            cfg.features.iter().any(|f| f == "bpq"),
            model.model_id() == "T3W1",
            "{}",
            model.model_id()
        );
    }
    // Every model.toml on disk is one of the enum variants above, so none escapes.
    let models_dir = workspace_dir().unwrap().join("models");
    for entry in std::fs::read_dir(&models_dir).unwrap() {
        let entry = entry.unwrap();
        if !entry.path().join("model.toml").exists() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        assert!(
            Model::value_variants().iter().any(|m| m.model_id() == id),
            "model dir {id} has no Model variant"
        );
    }
}
