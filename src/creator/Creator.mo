import Principal "mo:base/Principal";
import Text "mo:base/Text";
import HashMap "mo:base/HashMap";
import Nat "mo:base/Nat";
import List "mo:base/List";
import Option "mo:base/Option";
import Bool "mo:base/Bool";
import Xpnft "../xpnft/xpnft";
import Cycles "mo:base/ExperimentalCycles";

shared (install) actor class Creator(creators : [Principal]) = this {
    private stable var data_collections : [(Text, Principal)] = [];

    var collections_map : HashMap.HashMap<Text, Principal> = HashMap.fromIter(data_collections.vals(), 0, Text.equal, Text.hash);

    private stable var data_creators : [Principal] = [];

    var creators_list : List.List<Principal> = List.fromArray(creators);

    func _isCreator(p : Principal) : Bool {
        func principalEquals(c : Principal) : Bool {
            Principal.equal(c, p);
        };

        let result = List.find(creators_list, principalEquals);
        Option.isSome(result);
    };

    public query func collections(identifier : Text) : async ?Principal {
        collections_map.get(identifier);
    };

    public shared (msg) func create_collection(identifier : Text, minter : Principal) : async Principal = async {
        // Assert that the caller is a creator
        assert _isCreator(msg.caller);
        // Assert that the collection does not already exist
        assert Option.isNull(collections_map.get(identifier));
        // Create the collection
        Cycles.add(100000000000);
        let collection = await Xpnft.XPNFT(Principal.toText(minter));
        let address = Principal.fromActor(collection);
        collections_map.put(identifier, address);
        Principal.fromActor(collection);
    };
};
