use crate::https::ServerState;
use axum::{
    routing::{get, post},
    Router,
};
use axum_htmx::HxRequestGuardLayer;

pub(crate) mod groups;
pub(crate) mod oauth2;
pub(crate) mod persons;

pub fn admin_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/persons", get(persons::view_persons_get))
        .route(
            "/person/{person_uuid}/view",
            get(persons::view_person_view_get),
        )
        .route("/groups", get(groups::view_groups_get))
        .route("/group/{group_uuid}/view", get(groups::view_group_view_get))
        .route("/oauth2", get(oauth2::view_oauth2_get));
    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}

pub fn admin_api_router() -> Router<ServerState> {
    let unguarded_router = Router::new()
        .route("/person/create", post(persons::create_person))
        .route("/person/{person_uuid}/remove", post(persons::remove_person))
        .route("/group/create", post(groups::create_group))
        .route("/group/{group_uuid}", post(groups::edit_group))
        .route("/group/{group_uuid}/remove", post(groups::remove_group))
        .route("/group/{group_uuid}/add_member", post(groups::add_member))
        .route(
            "/group/{group_uuid}/remove_member",
            post(groups::remove_member),
        );

    let guarded_router = Router::new().layer(HxRequestGuardLayer::new("/ui"));

    Router::new().merge(unguarded_router).merge(guarded_router)
}
