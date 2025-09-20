use pnet::datalink::interfaces;

pub fn list_interfaces() -> Result<(), String> {
    for interface in interfaces() {
        println!("{}", interface);
    }
    Ok(())
}
